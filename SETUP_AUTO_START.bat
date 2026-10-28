@echo off
setlocal EnableExtensions
cd /d "%~dp0"
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Please right-click this file and choose Run as administrator.
  pause
  exit /b 1
)
if not exist server.js (
  echo ERROR: server.js not found. Extract the complete system folder first.
  pause
  exit /b 1
)
where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Node.js is not installed or not in PATH. Install Node.js 20 or newer, then retry.
  pause
  exit /b 1
)
if not exist node_modules (
  echo Installing dependencies. Internet is needed for this first-time setup.
  call npm install
  if errorlevel 1 (
    echo ERROR: npm install failed. Fix this before enabling automatic startup.
    pause
    exit /b 1
  )
)
set "TASKNAME=Nasim Local Server"
set "RUNFILE=%~dp0RUN_SERVER_AUTO.bat"
schtasks /Create /TN "%TASKNAME%" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR "\"%RUNFILE%\"" /F
if errorlevel 1 (
  echo ERROR: Could not create the scheduled task.
  pause
  exit /b 1
)
schtasks /Run /TN "%TASKNAME%"
echo.
echo Automatic startup task created. The server starts at Windows startup and retries if it stops.
echo Local staff should use the server IP address and port 3000.
echo Test this after restarting the computer before using it for live bookings.
pause
