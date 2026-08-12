@echo off
REM Build both virtualenvs on a fresh machine, then check what is still missing.
REM
REM Run from the omniswitch_ci_cd folder:  scripts\setup.bat
REM
REM What this cannot do for you, because it is machine-specific rather than
REM installable, is listed by check_env.py at the end: the console COM port,
REM nmap and tshark on PATH, an elevated shell, and configs\lab.yaml itself.

setlocal
set CI_CD=%~dp0..
set API=%CI_CD%\..\omniswitch_api_poc

echo === omniswitch_ci_cd ===
pushd "%CI_CD%" || exit /b 1
python -m venv venv || goto :failed
venv\Scripts\python.exe -m pip install --upgrade pip || goto :failed
venv\Scripts\python.exe -m pip install -e .[dev,web] || goto :failed
venv\Scripts\python.exe -m playwright install chromium || goto :failed
popd

echo.
echo === omniswitch_api_poc ===
if not exist "%API%" (
    echo   NOT FOUND at %API%
    echo   Clone it next to this repo, or set api_poc_path in configs\lab.yaml.
    goto :labfile
)
pushd "%API%" || exit /b 1
python -m venv venv || goto :failed
venv\Scripts\python.exe -m pip install --upgrade pip || goto :failed
venv\Scripts\python.exe -m pip install -e .[dev,web,ssh,serial] || goto :failed
venv\Scripts\python.exe -m playwright install chromium || goto :failed
popd

:labfile
echo.
pushd "%CI_CD%"
if not exist configs\lab.yaml (
    copy configs\lab.example.yaml configs\lab.yaml >nul
    echo Created configs\lab.yaml from the example -- fill it in before running.
)

echo.
echo === environment check ===
venv\Scripts\python.exe scripts\check_env.py
popd
exit /b %errorlevel%

:failed
echo.
echo Setup failed. Fix the error above and run scripts\setup.bat again.
popd
exit /b 1
