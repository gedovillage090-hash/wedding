@echo off
setlocal
cd /d "%~dp0"
if not exist server.js exit /b 2
:LOOP
where node >nul 2>nul
if errorlevel 1 (
  timeout /t 15 /nobreak >nul
  goto LOOP
)
node server.js
rem If the server exits unexpectedly, wait and start it again.
timeout /t 5 /nobreak >nul
goto LOOP
