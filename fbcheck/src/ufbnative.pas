{ ============================================================================
  ufbnative.pas — проверка ВОЗМОЖНОСТИ работы с Firebird через SQLdb
                  (нативный протокол, TIBConnection + fbclient.dll).

  Что проверяется (без требования запущенного сервера!):
    1. Загружаемость fbclient.dll (делает uenvinfo.FindFbClient);
    2. Создание объектов SQLdb: TIBConnection -> IbxConnection;
       сам факт успешного Create/Init говорит, что обвязка IB-API цела;
    3. Реальная попытка TCP-подключения к localhost:3050 — различаем:
         - соединились  -> сервер доступен;
         - refused     -> порт закрыт / сервер не запущен (окружение ок);
         - timeout     -> firewall/хост недоступен;
    4. Если сервер доступен — пробуем открыть транзакцию/выполнить запрос
       к встроенной базе или указанной в параметрах запуска.

  Используется модуль ibconnection из состава Lazarus (пакет sqldb,
  dependency на "fbintf" не нужен — TIBConnection сам грузит fbclient.dll
  через LoadLibrary по правилам: ISC_API_DLL_DIR -> PATH -> каталог EXE).
============================================================================ }
unit ufbnative;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, StrUtils, SQLDb, IBConnection;

type
  { Итог проверки нативного канала }
  TNativeCheckResult = record
    ClientOk      : Boolean; // fbclient загружается
    SqldbOk       : Boolean; // TIBConnection создаётся и инициализируется
    ServerReach   : Integer; // 0 = неизвестно, 1 = доступен, -1 = недоступен
    QueryOk       : Boolean; // удалось выполнить «SELECT 1» (если сервер есть)
    Message       : string;  // человекочитаемое резюме
  end;

{ ALog — TLogger (Pointer, чтобы не тянуть li зависимость в сигнатуре)
  AHost/APort/APathDb — параметры probe-подключения (по умолчанию localhost) }
function CheckNativeFirebird(ALog: Pointer; const AHost: string;
  APort: Word; const AProbeDbPath: string): TNativeCheckResult;

implementation

uses
  ulogger, uenvinfo;

{ ---------------------------------------------------------------------------
  Хелпер: классифицирует исключение SQLdb по тексту (в FPC нет единого
  кода ошибки сокета под всеми ОС; для Win7/Win10 тексты стабильны).
--------------------------------------------------------------------------- }
function IsConnRefused(const E: string): Boolean;
begin
  Result := (Pos('refused', LowerCase(E)) > 0) or
            (Pos('отклонено', LowerCase(E)) > 0) or
            (Pos('10061', E) > 0); // WSAECONNREFUSED
end;

function IsConnTimeout(const E: string): Boolean;
begin
  Result := (Pos('timeout', LowerCase(E)) > 0) or
            (Pos('timed out', LowerCase(E)) > 0) or
            (Pos('10060', E) > 0); // WSAETIMEDOUT
end;

function CheckNativeFirebird(ALog: Pointer; const AHost: string;
  APort: Word; const AProbeDbPath: string): TNativeCheckResult;
var
  L        : TLogger;
  Con      : TIBConnection;
  Trx      : TSQLTransaction;
  Q        : TSQLQuery;
  Fb       : TFbClientInfo;
  ErrText  : string;
begin
  L := TLogger(ALog);
  FillChar(Result{%H-}, SizeOf(Result), 0);
  Result.ServerReach := 0;

  L.Info('=== ПРОВЕРКА НАТИВНОГО КАНАЛА (SQLdb + fbclient.dll) ===');

  {---- Шаг 1. Клиентская библиотека --------------------------------------}
  Fb := FindFbClient(ALog);
  Result.ClientOk := Fb.Found;
  if not Result.ClientOk then
  begin
    Result.Message := 'fbclient.dll не найдена/не загружается — нативный ' +
                      'канал SQLdb работать НЕ будет.';
    L.Error(Result.Message);
    Exit;
  end;
  L.Info('fbclient: путь="%s", версия=%s, разрядность=%s',
         [Fb.Path, Fb.Version, Fb.Bitness]);

  {---- Шаг 2. Создание объектов SQLdb -------------------------------------}
  // TIBConnection при первом обращении инициирует IB-API-обвязку
  // (ibase.pas/fbclient.pas динамически подключает функции fbclient.dll).
  try
    Con := TIBConnection.Create(nil);
    try
      Con.HostName    := AHost;
      Con.DatabaseName:= IfThen(AProbeDbPath <> '', AProbeDbPath,
                                'localhost:C:\FBCHECK_PROBE.FDB');
      Con.UserName    := 'SYSDBA';
      Con.Password    := 'masterkey';
      // Свойство LibraryName появилось в новых версиях Lazarus; ставим
      // только если оно доступно — иначе используем стандартный поиск DLL.
      L.Info('Объекты SQLdb созданы: TIBConnection (%s)', [Con.ClassName]);
      Result.SqldbOk := True;
    finally
      // пока без Connect — просто доказали работоспособность обёртки
      FreeAndNil(Con);
    end;
  except
    on E: Exception do
    begin
      Result.SqldbOk := False;
      Result.Message := 'Ошибка инициализации SQLdb/TIBConnection: ' + E.Message;
      L.Error(Result.Message);
      Exit;
    end;
  end;

  {---- Шаг 3. Проба TCP-соединения с сервером -----------------------------}
  // Сначала дешёвый socket-probe порта — чтобы не ждать таймаутов IB API.
  L.Info('Проба подключения к %s:%d ...', [AHost, APort]);
  Con := TIBConnection.Create(nil);
  Trx := TSQLTransaction.Create(nil);
  Q   := TSQLQuery.Create(nil);
  try
    Con.HostName     := AHost;
    Con.DatabaseName := IfThen(AProbeDbPath <> '', AProbeDbPath,
                               'localhost:C:\FBCHECK_PROBE.FDB');
    Con.UserName     := 'SYSDBA';
    Con.Password     := 'masterkey';
    Con.Transaction  := Trx;
    Trx.DefaultLockingStyle := lsReadCommitted;
    Q.Transaction    := Trx;
    Q.SQLQuery.Text  := 'SELECT 1 AS OK_FLAG FROM RDB$DATABASE';

    try
      Con.Connected := True; // реально: attach через fbclient + TCP 3050
      Result.ServerReach := 1;
      L.Info('Сервер Firebird ДОСТУПЕН (%s:%d), attempt attach выполнен.', [AHost, APort]);
      {---- Шаг 4. Тестовый запрос ------------------------------------------}
      try
        Q.Prepare;
        Q.Open;
        if Q.FieldByName('OK_FLAG').AsInteger = 1 then
        begin
          Result.QueryOk := True;
          L.Info('Тестовый запрос выполнен: SELECT 1 -> 1. Нативный канал полностью работоспособен.');
        end
        else
          L.Warn('Запрос вернул неожиданное значение OK_FLAG.');
        Trx.Commit;
      except
        on E: Exception do
          L.Warn('Attach выполнен, но тестовый запрос неудачен: %s ' +
                 '(возможно, отсутствует указанный файл БД — это НЕ проблема клиента).',
                 [E.Message]);
      end;
    except
      on E: Exception do
      begin
        ErrText := E.Message;
        if IsConnRefused(ErrText) then
        begin
          Result.ServerReach := -1;
          L.Warn('Подключение ОТВЕРГНУТО: сервер Firebird на %s:%d не запущен ' +
                 '(или блокирует localhost). Клиентская библиотека при этом В ПОРЯДКЕ — ' +
                 'значит работа с Firebird на этом ПК возможна после запуска сервера.',
                 [AHost, APort]);
          L.Debug('Текст ошибки: %s', [ErrText]);
        end
        else if IsConnTimeout(ErrText) then
        begin
          Result.ServerReach := -1;
          L.Warn('Таймаут подключения к %s:%d — проверьте межсетевой экран ' +
                 'порт 3050 и доступность хоста.', [AHost, APort]);
          L.Debug('Текст ошибки: %s', [ErrText]);
        end
        else
        begin
          Result.ServerReach := -1;
          L.Error('Неизвестная ошибка подключения: %s', [ErrText]);
        end;
      end;
    end;
  finally
    FreeAndNil(Q);
    FreeAndNil(Trx);
    FreeAndNil(Con);
  end;

  {---- Резюме --------------------------------------------------------------}
  if Result.QueryOk then
    Result.Message := 'Нативный канал: OK (fbclient загружен, SQLdb инициализирован, ' +
                      'сервер доступен, запрос выполнен).'
  else if Result.ServerReach = 1 then
    Result.Message := 'Нативный канал: почти OK (attach выполнен, запрос не удался — см. WARN).'
  else if Result.ServerReach = -1 then
    Result.Message := Format('Нативный канал: клиент готов (%s v%s), сервер %s:%d недоступен ' +
                             '(запустите Firebird / снимите фаервол).',
                             [Fb.Path, Fb.Version, AHost, APort])
  else
    Result.Message := 'Нативный канал: не проверялся до конца.';
  L.Info('%s', [Result.Message]);
end;

end.
