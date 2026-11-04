@echo off
rem ============================================================================
rem build.cmd — сборка fbcheck.exe компилятором FPC без Lazarus IDE.
rem FPC 3.2.2+ из состава Lazarus 4.8. Запустите из каталога проекта.
rem При необходимости поправьте LAZDIR под свою установку Lazarus.
rem ============================================================================

setlocal
set LAZDIR=c:\lazarus
set FPC=%LAZDIR%\fpc\3.2.2\bin\i386-win32\fpc.exe
set SQLDBPATH=%LAZDIR%\components\sqldb

if not exist "%FPC%" set FPC=fpc.exe

echo [INFO] Компилятор: %FPC%
echo [INFO] SQLdb:      %SQLDBPATH%

"%FPC%" -MObjFPC -Scghi -O1 ^
  -Fu"%SQLDBPATH%" -Fu"%SQLDBPATH%\firebird" -Fu"%SQLDBPATH%\odbc" ^
  -Fusrc ^
  fbcheck.lpr -ofbcheck.exe

if errorlevel 1 (
  echo [ERROR] Сборка не удалась. Проверьте пути LAZDIR/SQLDBPATH.
  exit /b 1
)
echo [OK] Получен fbcheck.exe (x86, работает на Windows 7 и 10).
endlocal
