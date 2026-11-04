{ ============================================================================
  fbcheck — консольная утилита проверки возможности работы с Firebird 5.0.4
            на Windows 7 / Windows 10 из-под SQLdb (Lazarus 4.8 / FPC).

  Проверяются ДВА независимых канала:
    A) НАТИВНЫЙ: fbclient.dll + TIBConnection (SQLdb/IBConnection)
       - поиск и фактическая загрузка fbclient/gds32 нужной разрядности;
       - создание объектов SQLdb;
       - probe TCP-подключения к серверу и тестовый SELECT 1.
    B) ODBC: зарегистрированный драйвер + DriverManager + SQLConnect по DSN
       - реестр (оба view), наличие и загружаемость DriverDLL;
       - SQLAllocHandle(ENV)/SQLSetEnvAttr;
       - по желанию — SQLConnect к DSN и SELECT 1 FROM RDB$DATABASE.

  Лог пишется одновременно в консоль и в файл fbcheck_<дата>.log.
  Код возврата процесса: 0 = хотя бы один канал полностью рабочий,
                          1 = частично (клиент OK, сервер недоступен),
                          2 = ни один канал не готов.

  Параметры запуска (все необязательны):
    --host=<имя|ip>        хост Firebird для probe (по умолчанию localhost)
    --port=<число>         порт (по умолчанию 3050)
    --db=<путь|алиас>      путь к probe-БД для нативного attach
    --dsn=<имя DSN>        ODBC DSN для реального подключения
    --user=<имя>           пользователь (SYSDBA)
    --password=<пароль>    пароль (masterkey)
    --debug                подробный лог (DEBUG)
    --help                 эта справка
============================================================================ }
program fbcheck;

{$mode objfpc}{$H+}
{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  Classes, SysUtils, StrUtils,
  ulogger, uenvinfo, ufbnative, fodbccheck;

var
  LogFile   : string;
  Log       : TLogger;
  Host      : string = 'localhost';
  Port      : Word   = 3050;
  ProbeDb   : string = '';
  Dsn       : string = '';
  UserName  : string = 'SYSDBA';
  UserPass  : string = 'masterkey';
  Dbg       : Boolean = False;
  NatRes    : TNativeCheckResult;
  OdbcRes   : TOdbcCheckResult;
  ExitCode  : Integer;
  i         : Integer;
  Param     : string;
  Lvl       : TLogLevel;

{ ---------------------------------------------------------------------------
  Разбор командной строки: "--name=value" или "--flag".
--------------------------------------------------------------------------- }
procedure ParseParams;
begin
  for i := 1 to ParamCount do
  begin
    Param := ParamStrUTF8(i);
    if SameText(Param, '--help') or SameText(Param, '-?') then
    begin
      Writeln('Использование: fbcheck [--host=h] [--port=n] [--db=path] ' +
              '[--dsn=name] [--user=u] [--password=p] [--debug]');
      Halt(0);
    end
    else if SameText(Param, '--debug') then
      Dbg := True
    else if Pos('--host=', Param) = 1 then
      Host := Copy(Param, 8, MaxInt)
    else if Pos('--port=', Param) = 1 then
      Port := StrToIntDef(Copy(Param, 8, MaxInt), 3050)
    else if Pos('--db=', Param) = 1 then
      ProbeDb := Copy(Param, 6, MaxInt)
    else if Pos('--dsn=', Param) = 1 then
      Dsn := Copy(Param, 7, MaxInt)
    else if Pos('--user=', Param) = 1 then
      UserName := Copy(Param, 8, MaxInt)
    else if Pos('--password=', Param) = 1 then
      UserPass := Copy(Param, 12, MaxInt)
    else
      Writeln(stderr, 'Неизвестный параметр: ', Param);
  end;
end;

begin
  { Имя лога: fbcheck_ГГГГММДД.log рядом с EXE }
  LogFile := ExtractFilePath(ParamStr(0)) +
             Format('fbcheck_%s.log', [FormatDateTime('yyyymmdd', Now)]);

  ParseParams;

  if Dbg then Lvl := llDebug else Lvl := llInfo;
  Log := TLogger.Create(LogFile, Lvl);
  try
    Log.Info('=========================================================');
    Log.Info(' FBCheck v1.0 — диагностика каналов Firebird (SQLdb/ODBC)');
    Log.Info(' Lazarus/FPC run-time, целевые ОС: Windows 7 / Windows 10');
    Log.Info(' Файл лога: %s', [LogFile]);
    Log.Info('=========================================================');
    Log.Info('ОС: %s', [GetOSDescription]);
    Log.Info('EXE: %s', [ParamStr(0)]);
    Log.Info('Параметры: host=%s port=%d db="%s" dsn="%s" user=%s debug=%s',
             [Host, Port, ProbeDb, Dsn, UserName, BoolToStr(Dbg, True)]);

    {---- Канал A: нативный fbclient ----------------------------------------}
    try
      NatRes := CheckNativeFirebird(Log, Host, Port, ProbeDb);
    except
      on E: Exception do
      begin
        NatRes.ClientOk := False;
        NatRes.Message  := 'НЕПЕРЕХВАЧЕННОЕ исключение нативной проверки: ' + E.Message;
        Log.Error(NatRes.Message);
        Log.Debug(E.StackTrace); // стек полезно писать только в DEBUG
      end;
    end;

    {---- Канал B: ODBC -------------------------------------------------------}
    try
      OdbcRes := CheckOdbcFirebird(Log, Dsn, UserName, UserPass);
      // дополнительно логируем доступные системные DSN (полезно оператору)
      if Dsn = '' then
        Log.Info('Доступные системные DSN для --dsn=: %s', [GetSystemDsnNames]);
    except
      on E: Exception do
      begin
        OdbcRes.Message := 'НЕПЕРЕХВАЧЕННОЕ исключение ODBC-проверки: ' + E.Message;
        Log.Error(OdbcRes.Message);
      end;
    end;

    {---- Сводка ------------------------------------------------------------}
    Log.Info('==================== СВОДКА ====================');
    Log.Info('[НАТИВНЫЙ fbclient] client=%s sqldb=%s server=%s query=%s',
             [BoolToStr(NatRes.ClientOk, True), BoolToStr(NatRes.SqldbOk, True),
              IntToStr(NatRes.ServerReach), BoolToStr(NatRes.QueryOk, True)]);
    Log.Info('  %s', [NatRes.Message]);
    Log.Info('[ODBC] driver=%s dll=%s loadable=%s env=%s connect=%s query=%s',
             [BoolToStr(OdbcRes.DriverRegistered, True),
              BoolToStr(OdbcRes.DriverDllExists, True),
              BoolToStr(OdbcRes.DriverLoadable, True),
              BoolToStr(OdbcRes.EnvOk, True),
              BoolToStr(OdbcRes.ConnectOk, True),
              BoolToStr(OdbcRes.QueryOk, True)]);
    Log.Info('  %s', [OdbcRes.Message]);

    if NatRes.QueryOk or OdbcRes.QueryOk then
      ExitCode := 0                       // полноценно работаем с Firebird
    else if (NatRes.ClientOk and NatRes.SqldbOk) or
            (OdbcRes.EnvOk and OdbcRes.DriverLoadable) then
      ExitCode := 1                       // клиенты готовы, нет сервера/DSN
    else
      ExitCode := 2;                      // окружение не пригодно

    Log.Info('Итоговый код возврата: %d (0=OK, 1=клиенты готовы без сервера, 2=неготово)',
             [ExitCode]);
  finally
    Log.Info('--- Конец журнала ---');
    FreeAndNil(Log);   // деструктор закроет файловый поток
  end;
  Halt(ExitCode);
end.
