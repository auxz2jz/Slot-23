@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 -m universal_decompiler.app
) else (
  python -m universal_decompiler.app
)
if errorlevel 1 (
  echo.
  echo Application did not start. Install Python 3.11+ for Windows with tkinter.
  pause
)
