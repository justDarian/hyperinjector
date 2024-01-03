@echo off
cd /d %~dp0

title Checking Python installation...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed! (Go to https://www.python.org/downloads and install the latest version.^)
    echo Make sure it is added to PATH
    goto ERROR
)

title Checking libraries...
python -m pip install -r requirements.txt

title Starting hyperinjector...
python hyperinjector.py
if %errorlevel% neq 0 goto ERROR
exit

:ERROR
color 4 && title [Error]
echo ERROR contact not.darian on Discord
pause > nul