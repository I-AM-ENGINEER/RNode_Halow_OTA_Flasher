@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

set "APP_PY_GUI=rnode-halow-flasher-gui.py"
set "APP_PY_CLI=rnode-halow-flasher.py"
set "VENV_DIR=.venv"
set "DIST_DIR=dist"
set "BUILD_DIR=build"
set "SPEC_NAME_GUI=rnode-halow-flasher-gui"
set "SPEC_NAME_CLI=rnode-halow-flasher"

if not exist "%APP_PY_GUI%" (
  echo [!] "%APP_PY_GUI%" not found in: %cd%
  exit /b 1
)

if not exist "%APP_PY_CLI%" (
  echo [!] "%APP_PY_CLI%" not found in: %cd%
  exit /b 1
)

if not exist "modules\" (
  echo [!] "modules\" folder not found in: %cd%
  exit /b 1
)

if not exist "embedded_fw\" mkdir "embedded_fw"

set "PY=python"
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
)

if not exist "%VENV_DIR%\Scripts\python.exe" (
  echo [*] Creating venv: %VENV_DIR%
  %PY% -m venv "%VENV_DIR%"
  if errorlevel 1 exit /b 1
)

set "VPY=%VENV_DIR%\Scripts\python.exe"
set "VPIP=%VENV_DIR%\Scripts\pip.exe"

echo [*] Upgrading pip/setuptools/wheel...
"%VPY%" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 exit /b 1

echo [*] Installing build deps...
"%VPIP%" install --upgrade -r requirements.txt pyinstaller
if errorlevel 1 exit /b 1

if exist "%DIST_DIR%\" rmdir /s /q "%DIST_DIR%"
if exist "%BUILD_DIR%\" rmdir /s /q "%BUILD_DIR%"
if exist "%SPEC_NAME_GUI%.spec" del /q "%SPEC_NAME_GUI%.spec" >nul 2>nul
if exist "%SPEC_NAME_CLI%.spec" del /q "%SPEC_NAME_CLI%.spec" >nul 2>nul

echo [*] Building GUI EXE...
"%VPY%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --noconsole ^
  --name "%SPEC_NAME_GUI%" ^
  --icon rns.ico ^
  --add-data "modules;modules" ^
  --add-data "embedded_fw;embedded_fw" ^
  --collect-all scapy ^
  --collect-all tftpy ^
  --hidden-import tftpy ^
  "%APP_PY_GUI%"

if errorlevel 1 (
  echo [!] GUI build failed.
  exit /b 1
)

echo [*] Building CLI EXE...
"%VPY%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --name "%SPEC_NAME_CLI%" ^
  --add-data "modules;modules" ^
  --add-data "embedded_fw;embedded_fw" ^
  --collect-all scapy ^
  --collect-all tftpy ^
  --hidden-import tftpy ^
  "%APP_PY_CLI%"

if errorlevel 1 (
  echo [!] CLI build failed.
  exit /b 1
)

echo.
echo [OK] Done:
echo     %cd%\%DIST_DIR%\%SPEC_NAME_GUI%.exe
echo     %cd%\%DIST_DIR%\%SPEC_NAME_CLI%.exe
echo.
pause
exit /b 0
