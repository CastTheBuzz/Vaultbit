@echo off
title Vaultbit setup
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is needed once. Installing it now...
  winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
  echo.
  echo Node.js installed. Close this window and double-click deploy.bat again.
  pause
  exit /b
)
node setup\setup.mjs
echo.
pause
