@echo off
rem Applies the v0.7a agent gateway patch (ADR-0016). RUN THIS YOURSELF: it changes protected guard files.
rem Safe to re-run: every run makes a NEW timestamped backup and restores it if anything fails.
setlocal EnableExtensions
cd /d "%~dp0\..\..\.."
set "REPO=%CD%"
if not exist "%REPO%\.claude\hooks\bash_guard.py" (
  echo ERROR: run this from the sentinel-security repo ^(.claude\hooks\bash_guard.py not found^).
  exit /b 1
)

rem Python checks run isolated (-I) from the Windows folder, never from the repo: an agent can write
rem files in the repo (a planted python.exe or json.py there must not run with your rights).
set "SAFE_CWD=%SystemRoot%"

for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "STAMP=%%T"
if "%STAMP%"=="" set "STAMP=%RANDOM%%RANDOM%"
set "BK=%REPO%\.claude\backup-before-gateway-%STAMP%"
mkdir "%BK%" || goto fail_backup
copy /Y "%REPO%\.claude\hooks\*.py" "%BK%\" >nul || goto fail_backup
copy /Y "%REPO%\.claude\settings.json" "%BK%\" >nul || goto fail_backup
echo Backed up current hooks and settings to %BK%

set "P=%REPO%\docs\patches\agent-gateway"
for %%F in (_policy.py _manifest.py _firewall.py _taint.py prompt_guard.py output_guard.py gateway.py _decision_log.py bash_guard.py protect_sensitive_files.py mcp_log.py session_log.py scan_written_file.py) do (
  copy /Y "%P%\%%F" "%REPO%\.claude\hooks\" >nul || goto restore
)
copy /Y "%P%\settings.merged.json" "%REPO%\.claude\settings.json" >nul || goto restore

pushd "%SAFE_CWD%"
python -I -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8')); print('settings JSON OK')" "%REPO%\.claude\settings.json"
if errorlevel 1 (popd & goto restore)
python -I -c "import sys; sys.path.insert(0, sys.argv[1]); import _policy, _manifest, _firewall, _taint, prompt_guard, output_guard, gateway; print('gateway imports OK')" "%REPO%\.claude\hooks"
if errorlevel 1 (popd & goto restore)
popd

echo.
echo DONE. Next steps:
echo   1. Start a NEW Claude Code conversation (or run "Developer: Reload Window" in VS Code).
echo   2. Run the guard tests:  uv run pytest -q tests\scenarios\test_s11_agent_policy_hooks.py
echo      The two "known bypass" tests on the live hooks must now PASS (they were expected failures).
echo   3. Pin the reviewed hooks (interactive terminal):  uv run sentinel agentlog pin-hooks --actor Parthiban
echo   4. Kill-switch drill, from the repo folder:  uv run sentinel agent kill-switch on
echo      ...then ask Claude to run "git status" (it must be refused, KS-01)
echo      ...then:  uv run sentinel agent kill-switch off
echo To undo: copy the files from %BK% back into .claude\hooks and .claude\settings.json
endlocal
exit /b 0

:fail_backup
echo ERROR: could not make a complete backup in %BK%. Nothing was changed.
endlocal
exit /b 1

:restore
echo ERROR: the patch did not apply cleanly. Restoring your previous files from %BK%.
rem Remove the new files first; the backup brings them back if a previous gateway was installed.
del "%REPO%\.claude\hooks\_policy.py" "%REPO%\.claude\hooks\gateway.py" "%REPO%\.claude\hooks\_manifest.py" "%REPO%\.claude\hooks\_firewall.py" "%REPO%\.claude\hooks\prompt_guard.py" "%REPO%\.claude\hooks\_taint.py" "%REPO%\.claude\hooks\output_guard.py" 2>nul
copy /Y "%BK%\*.py" "%REPO%\.claude\hooks\" >nul
copy /Y "%BK%\settings.json" "%REPO%\.claude\settings.json" >nul
endlocal
exit /b 1
