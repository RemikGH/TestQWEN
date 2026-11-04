# FBCheck — диагностика каналов Firebird 5.0.4 (SQLdb / нативный fbclient / ODBC)

Консольная программа на **Object Pascal** (**Lazarus 4.8 / FPC 3.2.2+**), проверяющая
возможность работы с **Firebird 5.0.4** на **Windows 7** и **Windows 10** двумя способами:

| Канал | Что проверяется |
|---|---|
| **A. Нативный (SQLdb + fbclient.dll)** | поиск `fbclient.dll`/`gds32.dll` (переменные `ISC_API_DLL_DIR`, каталоги установки Firebird, System32/SysWOW64, PATH, каталог EXE); фактическая загрузка через `LoadLibrary` (контроль разрядности x86/x64 по PE-заголовку); определение версии DLL; создание `TIBConnection`; probe TCP-подключения к `host:port`; тестовый `SELECT 1 FROM RDB$DATABASE` |
| **B. ODBC** | регистрация Firebird/InterBase ODBC-драйвера в реестре (оба view: 64- и 32-битных); наличие файла `DriverDLL`; его загружаемость (разрядность); живой контакт с ODBC DriverManager (`SQLAllocHandle(ENV)`); при заданном DSN — `SQLConnect` + `SELECT 1 FROM RDB$DATABASE` |

Лог пишется **одновременно в консоль и в файл** `fbcheck_ГГГГММДД.log` (рядом с EXE).

## Структура проекта

```
fbcheck/
├── fbcheck.lpr          — главный модуль (парсинг параметров, сводка, коды возврата)
├── fbcheck.lpi          — проект Lazarus 4.8 (BuildModes: Debug/ReleaseWin32/ReleaseWin64)
├── build.cmd            — сборка чистым fpc.exe без IDE
└── src/
    ├── ulogger.pas      — потокобезопасный логгер (консоль + UTF-8 файл, уровни DEBUG..ERROR)
    ├── uenvinfo.pas     — ОС (RtlGetVersion), разрядность процесса, поиск/загрузка fbclient,
    │                      версия DLL (VS_FIXEDFILEINFO), PE-bitness, ODBC-драйверы из реестра
    ├── ufbnative.pas    — проверка канала SQLdb/TIBConnection (+ probe сервера, SELECT 1)
    └── fodbccheck.pas   — проверка ODBC-канала (реестр → LoadLibrary → SQLAllocHandle →
                           SQLConnect → SQLExecDirect/SQLFetch/SQLGetData)
```

## Сборка

### Вариант 1 — Lazarus IDE
Открыть `fbcheck.lpi`. В Project Inspector должна быть зависимость от пакета **SQLdb**
(содержит `sqldb.pas`, `ibconnection.pas`). Выбрать режим `ReleaseWin32` (для Windows 7)
или `ReleaseWin64` (для Windows 10 x64 + Firebird x64) и собрать (Ctrl+F9).

### Вариант 2 — только компилятор
Запустить `build.cmd` (поправьте `LAZDIR`, если Lazarus установлен не в `c:\lazarus`).

> **Важно про разрядность:** собирайте **x86**, если на целевой машине стоит
> 32-битный клиент Firebird / 32-битный ODBC-драйвер, и **x64** для 64-битных.
> Программа сама диагностирует эту ошибку (WinError 193) и пишет её в лог.

## Запуск и параметры

```
fbcheck [--host=h] [--port=n] [--db=path] [--dsn=name]
        [--user=u] [--password=p] [--debug] [--help]
```

Примеры:

```bat
:: базовая диагностика окружения (без запущенного сервера тоже полезна)
fbcheck --debug

:: нативный канал к локальному FB5 + реальная probe-база
fbcheck --host=localhost --port=3050 --db="localhost:C:\DATA\TEST.FDB" ^
        --user=SYSDBA --password=masterkey

:: плюс проверка ODBC по существующему DSN
fbcheck --dsn=FB5_TEST --user=SYSDBA --password=masterkey --debug
```

## Коды возврата процесса

| Код | Значение |
|---|---|
| 0 | хотя бы один канал полностью рабочий (запрос выполнен) |
| 1 | клиенты готовы (fbclient грузится / ODBC-драйвер работает), но сервер или DSN недоступны |
| 2 | ни один канал не готов (нет fbclient нужной разрядности и нет ODBC-драйвера) |

## Типичные находки диагностики

* **WinError 193 (`%1 is not a valid Win32 application`)** — несовпадение разрядности
  `fbclient.dll`/ODBC-драйвера и EXE. Решение: пересобрать под нужную платформу
  либо положить DLL соответствующей битности рядом с EXE.
* **GetVersionEx врёт про «Windows 8»** на Windows 10 — здесь использован
  `RtlGetVersion` из `ntdll`, дающий честный build (10.0.x для Win10, 6.1.7601 для Win7).
* **32-битный процесс не видит 64-битный ODBC-драйвер** — реестр читается сразу
  в двух view (`KEY_WOW64_64KEY` + `KEY_WOW64_32KEY`), поэтому список драйверов полный.
* **«Server rejected attachment» / GDS code** при `--db` к несуществующей базе — это
  ошибка сервера, а не клиента: сам факт ответа означает, что нативный канал жив.

## Безопасность

Пароли из командной строки видны в списке процессов — для production-проверок
используйте временные креды или запускайте утилиту из защищённой сессии.
