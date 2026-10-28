@echo off
setlocal
cd /d "%~dp0"
title Nasim Wedding Management - Local Server
where node >nul 2>nul
if errorlevel 1 goto NONODE
if not exist package.json goto NOPROJECT
if not exist node_modules goto INSTALL
:RUN
start "Nasim Browser" cmd /c "timeout /t 2 >nul & start http://localhost:3000"
npm start
if errorlevel 1 goto STARTFAIL
goto END
:INSTALL
echo Installing required packages. This may take a few minutes...
npm install
if errorlevel 1 goto INSTALLFAIL
goto RUN
:NONODE
echo Node.js was not found. Install Node.js 20 or newer from https://nodejs.org/ then run this file again.
pause
goto END
:NOPROJECT
echo ERROR: package.json was not found. Extract the entire ZIP folder before running this file.
pause
goto END
:INSTALLFAIL
echo ERROR: Package installation failed. Check your internet connection and the messages above.
pause
goto END
:STARTFAIL
echo ERROR: The server stopped. Read the error messages above.
pause
goto END
:END
endlocal
