@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Right-click this file and choose Run as administrator.
  pause
  exit /b 1
)
netsh advfirewall firewall delete rule name="Nasim Wedding System LAN 3000" >nul 2>&1
netsh advfirewall firewall add rule name="Nasim Wedding System LAN 3000" dir=in action=allow protocol=TCP localport=3000 profile=private
if %errorlevel% equ 0 (echo Firewall rule added for Private network only.) else (echo Failed to add firewall rule.)
pause
