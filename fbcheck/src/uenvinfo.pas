{ ============================================================================
  uenvinfo.pas — сбор информации об окружении Windows: версия ОС, разрядность,
                  поиск нативной клиентской библиотеки Firebird
                  (fbclient.dll / gds32.dll), список ODBC-драйверов и DSN.

  Почему это важно для проверки подключения к Firebird 5.0.4:
    1) fbclient.dll ОБЯЗАТЕЛЬНО должен совпадать по разрядности (x86/x64)
       с нашим исполняемым файлом, иначе LoadLibrary вернёт ошибку 193
       (ERROR_BAD_EXE_FORMAT) — классическая проблема «на одной машине
       работает, на другой нет»;
    2) единицы подключения SQLdb (TIBConnection) используют либо
       fbclient.dll, либо aliased gds32.dll;
    3) переменные окружения ISC_API_DLL_DIR / FB_API_DLL_DIR подсказывают,
       где искать клиентскую DLL;
    4) ODBC-драйвер Firebird регистрируется в реестре:
       HKLM\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers — читаем оба view
       (64- и 32-битный), чтобы не пропустить драйвер под WOW64.

  Специфичные WinAPI-вызовы защищены {$IFDEF USE_WIN_API}.
============================================================================ }
unit uenvinfo;

{$mode objfpc}{$H+}
{$IFDEF WINDOWS}{$DEFINE USE_WIN_API}{$ENDIF}

interface

uses
  Classes, SysUtils
  {$IFDEF USE_WIN_API}, Windows, Registry{$ENDIF};

type
  { Результат поиска клиентской библиотеки Firebird }
  TFbClientInfo = record
    Found      : Boolean;   // найдена ли хотя бы одна загружаемая DLL
    Path       : string;    // полный путь к первой успешно загруженной
    Bitness    : string;    // 'x86' / 'x64' / '?' (по PE-заголовку)
    Version    : string;    // версия файла из VS_VERSION_INFO ('?' если нет)
  end;

function  GetOSDescription: string;   // "Windows 7 (build 7601)...", "Windows 10..."
function  SelfBitness: string;        // разрядность НАШЕГО exe: x86 / x64
function  GetDllBitness(const APath: string): string; // разрядность DLL по PE
function  FindFbClient(ALog: Pointer): TFbClientInfo; // ALog — TLogger
procedure ListOdbcDrivers(Drivers: TStringList);      // из реестра, оба view
function  OdbcDriverPath(const ADriverName: string): string; // DriverDll из реестра
function  GetSystemDsnNames: string;  // список настроенных системных DSN

implementation

uses
  ulogger;

{$IFDEF USE_WIN_API}

{ ---------------------------------------------------------------------------
  Разворачивает %VARS% в строке (ExpandEnvironmentStrings).
--------------------------------------------------------------------------- }
function ExpandEnv(const AS: string): string;
var
  Buf: array[0..32767] of Char;
begin
  if ExpandEnvironmentStrings(PChar(AS), Buf, Length(Buf)) > 0 then
    Result := Buf
  else
    Result := AS;
end;

{ ---------------------------------------------------------------------------
  Точная версия Windows через RtlGetVersion из ntdll.dll.

  ВАЖНО: GetVersionEx() на Windows 10 возвращает 6.2, если в манифесте EXE
  не объявлена поддержка 10.0 — типичная ловушка диагностики. RtlGetVersion
  не подвержен этому и корректно работает и на Windows 7, и на Windows 10.
--------------------------------------------------------------------------- }
type
  RTL_OSVERSIONINFOEXW = record
    dwOSVersionInfoSize: LongWord;
    dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId: LongWord;
    szCSDVersion: array[0..127] of WideChar;
    wServicePackMajor, wServicePackMinor: Word;
    wSuiteMask: Word;
    wProductType, wReserved: Byte;
  end;
  PRTL_OSVERSIONINFOEXW = ^RTL_OSVERSIONINFOEXW;

function GetOSDescription: string;
var
  hNtdll : THandle;
  RtlGV  : function(v: PRTL_OSVERSIONINFOEXW): LongInt; stdcall;
  vi     : RTL_OSVERSIONINFOEXW;
  Name   : string;
begin
  Result := '';
  hNtdll := GetModuleHandle('ntdll');
  if hNtdll = 0 then
    hNtdll := LoadLibrary('ntdll');
  if hNtdll <> 0 then
  begin
    Pointer(RtlGV) := GetProcAddress(hNtdll, 'RtlGetVersion');
    if Assigned(RtlGV) then
    begin
      FillChar(vi{%H-}, SizeOf(vi), 0);
      vi.dwOSVersionInfoSize := SizeOf(vi);
      if RtlGV(@vi) = 0 then // STATUS_SUCCESS
      begin
        if (vi.dwMajorVersion = 6) and (vi.dwMinorVersion = 1) then
          Name := 'Windows 7 / Server 2008 R2'
        else if (vi.dwMajorVersion = 6) and (vi.dwMinorVersion = 3) then
          Name := 'Windows 8.1'
        else if vi.dwMajorVersion = 10 then
          Name := 'Windows 10 / Server 2016+'
        else
          Name := Format('Windows %d.%d', [vi.dwMajorVersion, vi.dwMinorVersion]);
        Result := Format('%s (build %d), SP %d.%d',
                         [Name, vi.dwBuildNumber,
                          vi.wServicePackMajor, vi.wServicePackMinor]);
        Exit;
      end;
    end;
  end;
  Result := 'Windows (версия не определена)';
end;

{ ---------------------------------------------------------------------------
  Работаем ли в WOW64 (32-битный процесс на 64-битной ОС)?
--------------------------------------------------------------------------- }
function IsWow64CurrentProcess: Boolean;
var
  hMod : THandle;
  pFun : function(h: THandle; out wow: LongBool): BOOL; stdcall;
  wow  : LongBool;
begin
  Result := False;
  hMod := GetModuleHandle('kernel32');
  if hMod = 0 then Exit;
  Pointer(pFun) := GetProcAddress(hMod, 'IsWow64Process'); // есть начиная с Win7
  if not Assigned(pFun) then Exit;
  if pFun(GetCurrentProcess, wow) then
    Result := Boolean(wow);
end;

{ ---------------------------------------------------------------------------
  Разрядность СОБСТВЕННОГО процесса. Именно столько «весит» та fbclient.dll,
  которую мы физически сможем загрузить.
--------------------------------------------------------------------------- }
function SelfBitness: string;
begin
{$IFDEF CPUX64}
  Result := 'x64';
{$ELSE}
  {$IFDEF CPU386}
    if IsWow64CurrentProcess then
      Result := 'x86 (32-битный процесс на 64-битной ОС / WOW64)'
    else
      Result := 'x86';
  {$ELSE}
    Result := '?';
  {$ENDIF}
{$ENDIF}
end;

{ ---------------------------------------------------------------------------
  Версия файла (DLL/EXE) из блока VS_FIXEDFILEINFO.

  В FPC тип PChar = PAnsiChar, а WinAPI-функции версии ожидают PWideChar
  (W-версии). Поэтому явно заводим UnicodeString и передаём PWideChar —
  иначе компилятор выдаст ошибку несовместимых типов.
--------------------------------------------------------------------------- }
function GetFileVersionStr(const APath: string): string;
var
  sz     : LongWord;
  lenRet : LongWord;
  buf    : pointer;
  vi     : PVSFixedFileInfo;
  viSize : LongWord;
  wpath  : UnicodeString;
begin
  Result := '?';
  wpath  := UTF8Decode(APath);
  sz := GetFileVersionInfoSizeW(PWideChar(wpath), lenRet);
  if sz = 0 then Exit;
  buf := nil;
  GetMem(buf, sz);
  try
    if GetFileVersionInfoW(PWideChar(wpath), 0, sz, buf) then
    begin
      if VerQueryValue(buf, '\', Pointer(vi), viSize) and
         (viSize >= SizeOf(VS_FIXEDFILEINFO)) and
         (vi^.dwSignature = $FEEF04BD) then
      begin
        Result := Format('%d.%d.%d.%d',
          [HiWord(vi^.dwFileVersionMS), LoWord(vi^.dwFileVersionMS),
           HiWord(vi^.dwFileVersionLS), LoWord(vi^.dwFileVersionLS)]);
      end;
    end;
  finally
    FreeMem(buf);
  end;
end;

{ ---------------------------------------------------------------------------
  Разрядность DLL по заголовку PE — БЕЗ загрузки в процесс:
    MZ -> e_lfanew (смещение $3C) -> 'PE\0\0' -> Word Machine
    $014C = i386, $8664 = AMD64, $AA64 = ARM64.
--------------------------------------------------------------------------- }
function GetDllBitness(const APath: string): string;
const
  SZ_SIZEOF_HEADERS = $40;
var
  f        : file;
  hdr      : array[0..$3F] of Byte;
  ntOff    : LongWord;
  sigBytes : array[0..3] of Byte;
  machine  : Word;
begin
  Result := '?';
  {$I-}
  AssignFile(f, APath);
  Reset(f, 1);
  try
    if FileSize(f) < SZ_SIZEOF_HEADERS + 6 then Exit;
    BlockRead(f, hdr, SizeOf(hdr));
    if IOResult <> 0 then Exit;
    if (hdr[0] <> Ord('M')) or (hdr[1] <> Ord('Z')) then Exit; // не MZ/PE
    ntOff := hdr[$3C] or (hdr[$3D] shl 8) or (hdr[$3E] shl 16) or (hdr[$3F] shl 24);
    if ntOff = 0 then Exit;
    Seek(f, ntOff);
    if IOResult <> 0 then Exit;
    BlockRead(f, sigBytes, 4);            // ожидаем 'PE\0\0'
    if IOResult <> 0 then Exit;
    if (sigBytes[0] <> $50) or (sigBytes[1] <> $45) then Exit;
    BlockRead(f, machine, 2);             // сразу за сигнатурой — поле Machine
    if IOResult <> 0 then Exit;
    case machine of
      $014c: Result := 'x86';
      $8664: Result := 'x64';
      $AA64: Result := 'ARM64';
    else
      Result := Format('?0x%.4x', [machine]);
    end;
  finally
    CloseFile(f);
  end;
  {$I+}
end;

{ ---------------------------------------------------------------------------
  Финальная проверка: реально ли DLL загружается в наш процесс
  (совпадение разрядности, отсутствие битых зависимостей). Сразу выгружаем.
--------------------------------------------------------------------------- }
function TryLoadLibraryCheck(const APath: string; out ErrCode: LongWord): Boolean;
var
  h: THandle;
begin
  Result  := False;
  ErrCode := 0;
  h := LoadLibrary(PChar(APath));
  if h <> 0 then
  begin
    Result := True;
    FreeLibrary(h);
  end
  else
    ErrCode := GetLastError;
end;

{ ---------------------------------------------------------------------------
  Типовые места установки Firebird 5.0.x / 4.0.x + системные каталоги DLL
  + папка рядом с EXE. Значения с %VAR% раскрываются через ExpandEnv.
--------------------------------------------------------------------------- }
const
  FB_DLL_NAMES : array[0..1] of string = ('fbclient.dll', 'gds32.dll');
  CANDIDATE_DIRS: array[0..6] of string = (
    '%ProgramFiles%\Firebird\Firebird_5_0',
    '%ProgramFiles(x86)%\Firebird\Firebird_5_0',
    '%ProgramFiles%\Firebird\Firebird_4_0',
    '%ProgramFiles(x86)%\Firebird\Firebird_4_0',
    '%windir%\System32',
    '%windir%\SysWOW64',
    '.'                          // рядом с нашим EXE («зелёная» поставка)
  );

{ ---------------------------------------------------------------------------
  Ищет fbclient/gds32, логирует каждый кандидат и результат загрузки.
  ALog передаётся как Pointer, чтобы не поднимать жёсткую зависимость
  порядка компиляции единиц; внутри приводится к TLogger.
--------------------------------------------------------------------------- }
function FindFbClient(ALog: Pointer): TFbClientInfo;
var
  L        : TLogger absolute ALog;
  i, j     : Integer;
  dir, envName, full: string;
  err      : LongWord;
  candidates: TStringList;
  wBuf     : UnicodeString;
  found    : Integer;
begin
  FillChar(Result{%H-}, SizeOf(Result), 0);
  Result.Bitness := '?';
  Result.Version := '?';

  L.Info('Поиск нативной клиентской библиотеки Firebird (fbclient.dll / gds32.dll)...');
  L.Info('Разрядность нашего процесса: %s', [SelfBitness]);

  candidates := TStringList.Create;
  try
    // 1) Переменные окружения — приоритет (ими пользуется и SQLdb/IbxConnection)
    for i := 0 to 1 do
    begin
      if i = 0 then envName := 'ISC_API_DLL_DIR' else envName := 'FB_API_DLL_DIR';
      dir := GetEnvironmentVariable(envName);
      if dir <> '' then
      begin
        L.Debug('Переменная окружения %s = "%s"', [envName, dir]);
        for j := Low(FB_DLL_NAMES) to High(FB_DLL_NAMES) do
          candidates.Add(IncludeTrailingPathDelimiter(ExpandEnv(dir)) + FB_DLL_NAMES[j]);
      end
      else
        L.Debug('Переменная %s не задана.', [envName]);
    end;

    // 2) Стандартные каталоги установки Firebird + System32/SysWOW64 + '.'
    for i := Low(CANDIDATE_DIRS) to High(CANDIDATE_DIRS) do
    begin
      dir := ExpandEnv(CANDIDATE_DIRS[i]);
      if (dir = '') or not DirectoryExists(dir) then Continue;
      for j := Low(FB_DLL_NAMES) to High(FB_DLL_NAMES) do
        candidates.Add(IncludeTrailingPathDelimiter(dir) + FB_DLL_NAMES[j]);
    end;

    // 3) Поиск через стандартный механизм Windows (PATH, AppPaths и др.)
    for j := Low(FB_DLL_NAMES) to High(FB_DLL_NAMES) do
    begin
      SetLength(wBuf, MAX_PATH + 1);
      found := SearchPathW(nil, PWideChar(UTF8ToUTF16(FB_DLL_NAMES[j])), nil,
                            MAX_PATH, PWideChar(wBuf), nil);
      if found > 0 then
      begin
        SetLength(wBuf, found);
        full := UTF8Encode(wBuf);
        if (full <> '') and (candidates.IndexOf(full) < 0) then
          candidates.Add(full);
      end;
      SetLength(wBuf, 0);
    end;

    // Дедупликация и перебор кандидатов: существование -> загрузка
    candidates.Sort;
    for i := 0 to candidates.Count - 1 do
    begin
      if (i > 0) and SameText(candidates[i], candidates[i - 1]) then Continue;
      full := candidates[i];
      if not FileExists(full) then Continue;
      L.Info('Кандидат #%d/%d: %s (разрядность по PE-заголовку: %s)',
             [i + 1, candidates.Count, full, GetDllBitness(full)]);
      if TryLoadLibraryCheck(full, err) then
      begin
        Result.Found   := True;
        Result.Path    := full;
        Result.Bitness := GetDllBitness(full);
        Result.Version := GetFileVersionStr(full);
        L.Info('  -> УСПЕХ: DLL загружается через LoadLibrary. Версия файла: %s, разрядность: %s',
               [Result.Version, Result.Bitness]);
        Break;
      end
      else
        L.Warn('  -> файл существует, но НЕ загружается (WinError=%d: %s). ' +
               'Типичная причина: разрядность DLL (%s) не совпадает с процессом (%s).',
               [err, SysErrorMessage(err), GetDllBitness(full), SelfBitness]);
    end;

    if not Result.Found then
      L.Error('Ни один из %d кандидатов fbclient.dll/gds32.dll не найден или не загружен. ' +
              'Нативное подключение SQLdb (TIBConnection) невозможно: установьте ' +
              'клиент Firebird нужной разрядности или скопируйте fbclient.dll рядом с EXE.',
              [candidates.Count]);
  finally
    candidates.Free;
  end;
end;

{ ---------------------------------------------------------------------------
  Чтение ODBC-драйверов из одного view реестра (64- или 32-битного).
--------------------------------------------------------------------------- }
procedure ReadOdbcDriversFromView(AAccess: LongWord; Drivers: TStringList);
var
  reg  : TRegistry;
  k    : Integer;
  names: TStringList;
begin
  reg := TRegistry.Create(KEY_READ or AAccess);
  try
    reg.RootKey := HKEY_LOCAL_MACHINE;
    if reg.OpenKeyReadOnly('SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers') then
    begin
      names := TStringList.Create;
      try
        reg.GetValueNames(names);
        for k := 0 to names.Count - 1 do
          if Drivers.IndexOf(names[k]) < 0 then
            Drivers.Add(names[k]);
      finally
        names.Free;
      end;
      reg.CloseKey;
    end;
  finally
    reg.Free;
  end;
end;

procedure ListOdbcDrivers(Drivers: TStringList);
begin
  Drivers.Clear;
  // Читаем ОБА view: 32-битный процесс по умолчанию видит только Wow6432Node,
  // поэтому явно запрашиваем KEY_WOW64_64KEY и KEY_WOW64_32KEY.
  ReadOdbcDriversFromView(KEY_WOW64_64KEY, Drivers);
  ReadOdbcDriversFromView(KEY_WOW64_32KEY,  Drivers);
end;

{ ---------------------------------------------------------------------------
  Путь к DriverDLL указанного ODBC-драйвера (для проверки существования).
--------------------------------------------------------------------------- }
function OdbcDriverPath(const ADriverName: string): string;
var
  reg : TRegistry;
begin
  Result := '';
  reg := TRegistry.Create(KEY_READ);
  try
    reg.RootKey := HKEY_LOCAL_MACHINE;
    if reg.OpenKeyReadOnly('SOFTWARE\ODBC\ODBCINST.INI\' + ADriverName) then
    begin
      if reg.ValueExists('DriverDll') then
        Result := reg.ReadString('DriverDll');
      reg.CloseKey;
    end;
  finally
    reg.Free;
  end;
end;

{ ---------------------------------------------------------------------------
  Имена системных DSN (HKLM\...\ODBC.INI).
--------------------------------------------------------------------------- }
function GetSystemDsnNames: string;
var
  reg : TRegistry;
  sl  : TStringList;
  s   : string;
begin
  Result := '';
  reg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  sl  := TStringList.Create;
  try
    reg.RootKey := HKEY_LOCAL_MACHINE;
    if reg.OpenKeyReadOnly('SOFTWARE\ODBC\ODBC.INI') then
    begin
      reg.GetKeyNames(sl);
      for s in sl do
        if CompareText(s, 'ODBC Data Sources') <> 0 then
          Result := Result + s + '; ';
      reg.CloseKey;
    end;
  finally
    sl.Free;
    reg.Free;
  end;
  if Result = '' then
    Result := '(системные DSN отсутствуют)';
end;

{$ELSE} // --------------------------------------------- заглушки не-Windows

function GetOSDescription: string;
begin
  Result := 'Не-Windows платформа (проверка рассчитана на Windows 7/10)';
end;

function SelfBitness: string;
begin
  Result := '?';
end;

function FindFbClient(ALog: Pointer): TFbClientInfo;
begin
  FillChar(Result{%H-}, SizeOf(Result), 0);
  TLogger(ALog).Warn('Поиск fbclient доступен только под Windows.');
end;

procedure ListOdbcDrivers(Drivers: TStringList);
begin
  Drivers.Clear;
end;

function OdbcDriverPath(const ADriverName: string): string;
begin
  Result := '';
end;

function GetSystemDsnNames: string;
begin
  Result := '(только Windows)';
end;

{$ENDIF}

end.
