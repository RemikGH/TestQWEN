{ ============================================================================
  fodbccheck.pas — проверка ВОЗМОЖНОСТИ работы с Firebird через существующий ODBC.

  Стратегия (от дешёвого к дорогому):
    1. Реестр: есть ли зарегистрированный ODBC-драйвер Firebird/InterBase
       и существует ли его DriverDLL на диске (uenvinfo.ListOdbcDrivers);
    2. Загрузка DriverDLL через LoadLibrary — доказательство, что разрядность
       драйвера совпадает с нашим процессом (x86/x64) — частый источник
       ошибок «Data source name not found and no default driver specified»;
    3. SQLAllocHandle(SQL_HANDLE_ENV) + SQLSetEnvAttr(ODBC 3.0) — минимальный
       живой контакт с ODBC DriverManager Windows;
    4. Если задан DSN — реальный SQLConnect и запрос
       «SELECT 1 FROM RDB$DATABASE» через SQLExecDirect/SQLFetch/SQLGetData.

  Модуль odbc32 из состава FPC описывает ANSI-API — достаточно для Win7/Win10.
============================================================================ }
unit fodbccheck;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TOdbcCheckResult = record
    DriverRegistered : Boolean; // в реестре найден FB/IB-драйвер
    DriverDllExists  : Boolean; // файл DriverDLL присутствует на диске
    DriverLoadable   : Boolean; // LoadLibrary успешен (разрядность ок)
    EnvOk            : Boolean; // ODBC Environment создан
    ConnectOk        : Boolean; // SQLConnect успешен (если был DSN)
    QueryOk          : Boolean; // SELECT 1 выполнен
    Message          : string;  // резюме
  end;

{ ALog — TLogger. ADsn — имя настроенного DSN ('' => шаг подключения пропускается).
  AUser/APassword — креды для SQLConnect. }
function CheckOdbcFirebird(ALog: Pointer; const ADsn, AUser, APassword: string): TOdbcCheckResult;

implementation

uses
  ulogger, uenvinfo;

{$IFDEF WINDOWS}
uses
  Windows, odbc32;

{ ---------------------------------------------------------------------------
  Извлекает текст последней диагностики ODBC (SQL_DIAGNOSTICS AREA 3)
  по хендлу нужного типа. Приоритет: stmt -> dbc -> env.
--------------------------------------------------------------------------- }
function OdbcErrorMessage(AEnv, ADbc, AStmt: Pointer): string;
var
  msg    : array[0..1023] of Char;
  stat   : array[0..7]     of Char;
  native : LongInt;
  lenMsg : SmallInt;
  hnd    : Pointer;
  hType  : SmallInt;
begin
  Result := '';
  FillChar(msg{%H-},  SizeOf(msg),  0);
  FillChar(stat{%H-}, SizeOf(stat), 0);
  lenMsg := 0;

  hnd   := nil;
  hType := 0;
  if AStmt <> nil then      begin hnd := AStmt; hType := SQL_HANDLE_STMT; end
  else if ADbc <> nil then  begin hnd := ADbc;  hType := SQL_HANDLE_DBC;  end
  else if AEnv <> nil then  begin hnd := AEnv;  hType := SQL_HANDLE_ENV;  end;

  if hnd = nil then
  begin
    Result := '(нет хендла для диагностики)';
    Exit;
  end;

  if SQLGetDiagRec(hType, hnd, 1, @stat[0], @native, @msg[0],
                   SizeOf(msg), @lenMsg) = SQL_SUCCESS then
    Result := Format('[SQLSTATE %s][native=%d] %s', [stat, native, msg])
  else
    Result := '(текст ODBC-ошибки недоступен)';
end;
{$ENDIF}

function CheckOdbcFirebird(ALog: Pointer; const ADsn, AUser, APassword: string): TOdbcCheckResult;
var
  L        : TLogger absolute ALog;
  drivers  : TStringList;
  i        : Integer;
  fbDrv    : string;      // имя первого Firebird/InterBase-драйвера
  drvPath  : string;      // путь DriverDLL
  errCode  : LongWord;
  h        : THandle;
{$IFDEF WINDOWS}
  env      : SQLHENV;
  dbc      : SQLHDBC;
  stmt     : SQLHSTMT;
  ret      : SmallInt;
  outLen   : SmallInt;
  verBuf   : array[0..255] of Char;
  dummy    : LongInt;
{$ENDIF}
begin
  FillChar(Result{%H-}, SizeOf(Result), 0);
  L.Info('=== ПРОВЕРКА ODBC-КАНАЛА (Firebird через существующий ODBC) ===');

  {---- Шаг 1. Драйвер в реестре --------------------------------------------}
  drivers := TStringList.Create;
  try
    ListOdbcDrivers(drivers);
    L.Info('Зарегистрированные ODBC-драйверы (%d шт.):', [drivers.Count]);
    for i := 0 to drivers.Count - 1 do
      L.Debug('  * %s', [drivers[i]]);

    fbDrv := '';
    for i := 0 to drivers.Count - 1 do
      if (Pos('firebird', LowerCase(drivers[i])) > 0) or
         (Pos('interbase', LowerCase(drivers[i])) > 0) then
      begin
        fbDrv := drivers[i];
        Break;
      end;

    Result.DriverRegistered := fbDrv <> '';
    if Result.DriverRegistered then
      L.Info('Найден Firebird/InterBase ODBC-драйвер: "%s"', [fbDrv])
    else
      L.Warn('ODBC-драйвер Firebird НЕ зарегистрирован. Установите Firebird ODBC ' +
             'Driver разрядностью, совпадающей с этим приложением.');
  finally
    drivers.Free;
  end;

  {$IFDEF WINDOWS}
  {---- Шаг 2. Файл DriverDLL и его загружаемость ----------------------------}
  if Result.DriverRegistered then
  begin
    drvPath := OdbcDriverPath(fbDrv);
    if (drvPath <> '') and FileExists(drvPath) then
    begin
      Result.DriverDllExists := True;
      L.Info('DriverDLL: "%s" (разрядность по PE-заголовку: %s)',
             [drvPath, GetDllBitness(drvPath)]);
      h := LoadLibrary(PChar(drvPath));
      if h <> 0 then
      begin
        Result.DriverLoadable := True;
        FreeLibrary(h);
        L.Info('DriverDLL успешно загружается в наш процесс — разрядность совместима.');
      end
      else
      begin
        errCode := GetLastError;
        L.Error('DriverDLL НЕ загружается (WinError=%d: %s). Ошибка 193 означает ' +
                'несовпадение разрядности: 32-битный драйвер нельзя использовать ' +
                'из 64-битного процесса и наоборот.', [errCode, SysErrorMessage(errCode)]);
      end;
    end
    else
      L.Error('Файл DriverDLL ("%s") не найден на диске — драйвер «сломан» в реестре.', [drvPath]);
  end;

  {---- Шаг 3. Живой контакт с ODBC DriverManager ----------------------------}
  env  := nil; dbc := nil; stmt := nil;
  ret  := SQLAllocHandle(SQL_HANDLE_ENV, nil, env);
  if (ret = SQL_SUCCESS) or (ret = SQL_SUCCESS_WITH_INFO) then
  begin
    Result.EnvOk := True;
    L.Info('SQLAllocHandle(ENV) успешен — ODBC DriverManager Windows работает.');
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, Pointer(SQL_OV_ODBC3), 0);

    {---- Шаг 4. SQLConnect + тестовый запрос --------------------------------}
    if (ADsn <> '') and (Result.DriverLoadable or Result.DriverRegistered) then
    begin
      ret := SQLAllocHandle(SQL_HANDLE_DBC, env, dbc);
      if (ret = SQL_SUCCESS) or (ret = SQL_SUCCESS_WITH_INFO) then
      begin
        // таймаут логина — 10 секунд, чтобы консоль не «висела»
        SQLSetConnectAttr(dbc, SQL_ATTR_LOGIN_TIMEOUT, Pointer(10), 0);
        ret := SQLConnect(dbc, PChar(ADsn), SQL_NTS,
                               PChar(AUser), SQL_NTS,
                               PChar(APassword), SQL_NTS);
        if (ret = SQL_SUCCESS) or (ret = SQL_SUCCESS_WITH_INFO) then
        begin
          Result.ConnectOk := True;
          L.Info('SQLConnect к DSN "%s" успешен.', [ADsn]);
          FillChar(verBuf{%H-}, SizeOf(verBuf), 0);
          if SQLGetInfo(dbc, SQL_DRIVER_VER, @verBuf, SizeOf(verBuf), outLen)
             = SQL_SUCCESS then
            L.Info('Версия ODBC-драйвера: %s', [verBuf]);

          if SQLAllocHandle(SQL_HANDLE_STMT, dbc, stmt) = SQL_SUCCESS then
          begin
            ret := SQLExecDirect(stmt, 'SELECT 1 AS OK_FLAG FROM RDB$DATABASE', SQL_NTS);
            if (ret = SQL_SUCCESS) or (ret = SQL_SUCCESS_WITH_INFO) then
            begin
              if SQLFetch(stmt) = SQL_SUCCESS then
              begin
                dummy := 0;
                if SQLGetData(stmt, 1, SQL_C_SLONG, @dummy, 0, @outLen) = SQL_SUCCESS then
                begin
                  if dummy = 1 then
                  begin
                    Result.QueryOk := True;
                    L.Info('Запрос через ODBC выполнен: SELECT 1 -> 1. ODBC-канал РАБОТОСПОСОБЕН.');
                  end
                  else
                    L.Warn('Неожиданное значение OK_FLAG=%d', [dummy]);
                end
                else
                  L.Warn('SQLGetData неудачен: %s', [OdbcErrorMessage(env, dbc, stmt)]);
              end
              else
                L.Warn('SQLFetch не вернул строку: %s', [OdbcErrorMessage(env, dbc, stmt)]);
              SQLFreeHandle(SQL_HANDLE_STMT, stmt);
              stmt := nil;
            end
            else
              L.Warn('SQLExecDirect неудачен: %s ' +
                     '(если база DSN недоступна — это проблема сервера/пути, а не канала ODBC).',
                     [OdbcErrorMessage(env, dbc, stmt)]);
          end;
          SQLDisconnect(dbc);
        end
        else
          L.Warn('SQLConnect к DSN "%s" НЕ удался: %s',
                 [ADsn, OdbcErrorMessage(env, dbc, nil)]);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        dbc := nil;
      end;
    end
    else if ADsn = '' then
      L.Info('DSN не задан параметром запуска — шаг SQLConnect пропущен ' +
             '(проверены регистрация драйвера, наличие DLL и работоспособность менеджера).')
    else
      L.Warn('Пропускаем SQLConnect: драйвер недоступен для загрузки.');

    SQLFreeHandle(SQL_HANDLE_ENV, env);
    env := nil;
  end
  else
    L.Error('SQLAllocHandle(ENV) не удался (ret=%d) — ODBC-подсистема Windows повреждена.', [ret]);

  {---- Резюме ---------------------------------------------------------------}
  if Result.QueryOk then
    Result.Message := 'ODBC-канал: ПОЛНОСТЬЮ РАБОТОСПОСОБЕН.'
  else if Result.EnvOk and Result.DriverLoadable then
    Result.Message := 'ODBC-канал: инфраструктура OK (драйвер грузится, менеджер работает); ' +
                      'реальное подключение не подтверждено (нет DSN/сервера).'
  else if Result.DriverRegistered then
    Result.Message := 'ODBC-канал: драйвер зарегистрирован, но не полностью проверен — ' +
                      'см. ошибки выше (чаще всего разрядность).'
  else
    Result.Message := 'ODBC-канал: драйвер Firebird не установлен — работа через ODBC невозможна.';
  L.Info('%s', [Result.Message]);
  {$ELSE}
  Result.Message := 'Проверка ODBC доступна только под Windows.';
  L.Warn('%s', [Result.Message]);
  {$ENDIF}
end;

end.
