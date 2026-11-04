{ ============================================================================
  ulogger.pas — простой потокобезопасный логгер для консольной утилиты FBCheck

  Назначение:
    - писать сообщения одновременно в консоль (stdout) и в текстовый файл;
    - поддерживать уровни: INFO / WARN / ERROR / DEBUG;
    - работать на Windows 7 / Windows 10 без зависимостей, кроме RTL.

  Автор: FBCheck (Lazarus/FPC, Object Pascal)
============================================================================ }
unit ulogger;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, DateUtils;

type
  { Уровни журналирования. Порядок важен: DEBUG < INFO < WARN < ERROR }
  TLogLevel = (llDebug, llInfo, llWarn, llError);

  { TLogger — логгер с выводом в консоль + файл }
  TLogger = class
  private
    FStream     : TFileStream;   // файловый поток (nil, если файл не открыт)
    FLock       : TCriticalSection;
    FMinLevel   : TLogLevel;     // минимальный уровень, ниже — игнорируем
    function LevelToTag(ALevel: TLogLevel): string;
    procedure WriteLine(ALevel: TLogLevel; const AMsg: string);
  public
    constructor Create(const AFileName: string; AMinLevel: TLogLevel = llInfo);
    destructor Destroy; override;
    procedure Debug(const AMsg: string); overload;
    procedure Info(const AMsg: string); overload;
    procedure Warn(const AMsg: string); overload;
    procedure Error(const AMsg: string); overload;
    // форматированный вариант: Log.Info('БД %s, таймаут %d мс', [Name, Timeout]);
    procedure Debug(const AFormat: string; const AArgs: array of Const); overload;
    procedure Info(const AFormat: string; const AArgs: array of Const); overload;
    procedure Warn(const AFormat: string; const AArgs: array of Const); overload;
    procedure Error(const AFormat: string; const AArgs: array of Const); overload;
    property MinLevel: TLogLevel read FMinLevel write FMinLevel;
  end;

implementation

{ ---------------------------------------------------------------------------
  Возвращает короткую текстовую метку уровня для префикса строки лога.
--------------------------------------------------------------------------- }
function TLogger.LevelToTag(ALevel: TLogLevel): string;
begin
  case ALevel of
    llDebug: Result := 'DEBUG';
    llInfo : Result := 'INFO ';
    llWarn : Result := 'WARN ';
    llError: Result := 'ERROR';
  else
    Result := '?????';
  end;
end;

constructor TLogger.Create(const AFileName: string; AMinLevel: TLogLevel);
begin
  inherited Create;
  FLock     := TCriticalSection.Create;
  FMinLevel := AMinLevel;
  FStream   := nil;
  try
    // fmCreate|fmShareDenyNone — чтобы можно было открыть лог, даже
    // когда он уже открыт другим процессом (например Notepad).
    FStream := TFileStream.Create(AFileName, fmCreate or fmShareDenyNone);
  except
    on E: Exception do
      Writeln(StdErr, '[WARN] Не удалось открыть файл лога "' + AFileName +
                      '": ' + E.Message + '. Логи только в консоль.');
  end;
end;

destructor TLogger.Destroy;
begin
  FreeAndNil(FStream);
  FreeAndNil(FLock);
  inherited Destroy;
end;

{ ---------------------------------------------------------------------------
  Центральный метод записи: timestamp + level + сообщение -> stdout и файл.
  Блокировка нужна, потому что проверки ODBC/fbclient могут идти из разных
  потоков (в текущей версии — из одного, но защита лишней не будет).
--------------------------------------------------------------------------- }
procedure TLogger.WriteLine(ALevel: TLogLevel; const AMsg: string);
var
  Line  : string;
  Buffer: UTF8String;
begin
  if ALevel < FMinLevel then Exit; // фильтр по уровню

  // ISO-подобная метка времени с миллисекундами
  Line := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) +
          ' [' + LevelToTag(ALevel) + '] ' + AMsg;

  FLock.Enter;
  try
    Writeln(Line);                       // консоль
    if FStream <> nil then
    begin
      // Пишем в файл в UTF-8 (с BOM при создании файла не делаем,
      // чтобы читался и Блокнотом Win7, и PowerShell без артефактов).
      Buffer := UTF8Encode(Line + sLineBreak);
      FStream.WriteBuffer(Buffer[1], Length(Buffer));
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TLogger.Debug(const AMsg: string);           begin WriteLine(llDebug, AMsg); end;
procedure TLogger.Info(const AMsg: string);            begin WriteLine(llInfo,  AMsg); end;
procedure TLogger.Warn(const AMsg: string);            begin WriteLine(llWarn,  AMsg); end;
procedure TLogger.Error(const AMsg: string);           begin WriteLine(llError, AMsg); end;

procedure TLogger.Debug(const AFormat: string; const AArgs: array of Const);
begin WriteLine(llDebug, Format(AFormat, AArgs)); end;

procedure TLogger.Info(const AFormat: string; const AArgs: array of Const);
begin WriteLine(llInfo, Format(AFormat, AArgs)); end;

procedure TLogger.Warn(const AFormat: string; const AArgs: array of Const);
begin WriteLine(llWarn, Format(AFormat, AArgs)); end;

procedure TLogger.Error(const AFormat: string; const AArgs: array of Const);
begin WriteLine(llError, Format(AFormat, AArgs)); end;

end.
