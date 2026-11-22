@echo off
setlocal
cd /d "%~dp0"
title Ritten // local control
where node.exe >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js 22 or newer is required.
  pause
  exit /b 1
)
node.exe -e "const major=Number(process.versions.node.split('.')[0]); if(major<22) process.exit(1)"
if errorlevel 1 (
  echo [ERROR] Ritten requires Node.js 22 or newer.
  pause
  exit /b 1
)
if not exist "dist\cli\index.js" (
  echo [ERROR] Ritten has not been built. From this folder run: npm.cmd run build
  pause
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1"
exit /b %errorlevel%
