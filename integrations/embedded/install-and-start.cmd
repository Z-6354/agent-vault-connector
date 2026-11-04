@echo off
rem One-click installer and launcher for the single-file local Vault.
rem Creates the data directory, initializes the SQLite database, then starts the
rem loopback-only service (127.0.0.1:3210) in a minimized background window.
setlocal
set "HERE=%~dp0"
set "VAULT_DIR=%USERPROFILE%\.hermes\vault"
set "DB=%VAULT_DIR%\vault.db"
set "ENV_FILE=%TEMP%\agent-vault-management.env"

rem ---- locate a Python 3 ----
set "PY="
py -3 -c "import sys; sys.exit(0)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
  python -c "import sys; sys.exit(0)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo [ERROR] Python 3 not found on PATH. Install Python 3.10+ first.
  pause & exit /b 1
)

rem ---- create dirs ----
if not exist "%VAULT_DIR%" mkdir "%VAULT_DIR%"

rem ---- initialize database + management env (idempotent: keeps existing data/passphrase) ----
echo [install] ensuring database is initialized ...
%PY% "%HERE%vault_server_local.py" install --db "%DB%"
if errorlevel 1 ( echo [ERROR] install failed & pause & exit /b 1 )

rem ---- verify service is not already running ----
%PY% "%HERE%vault_server_local.py" status --db "%DB%" | findstr /C:"service:" >nul 2>&1

rem ---- start the background service (minimized, auto-unlock for one-click UX) ----
echo [start] launching vault-local on http://127.0.0.1:3210 (background) ...
start "vault-local" /min %PY% "%HERE%vault_server_local.py" serve --db "%DB%" --auto-unlock
timeout /t 2 /nobreak >nul
%PY% "%HERE%vault_server_local.py" status --db "%DB%"
echo.
echo Done. Local Vault is running on 127.0.0.1:3210 (loopback only).
echo Management env: %ENV_FILE%
echo Database:        %DB%
pause
endlocal
