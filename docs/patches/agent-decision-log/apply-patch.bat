@echo off
rem Applies the agent decision log patch. RUN THIS YOURSELF (it changes protected guard files).
rem Safe to re-run. Backs up the current hooks and settings first; restores them if the new settings are not valid JSON.
setlocal
cd /d "%~dp0\..\..\.."
if not exist ".claude\hooks\bash_guard.py" (
  echo ERROR: run this from the sentinel-security repo ^(.claude\hooks\bash_guard.py not found^).
  exit /b 1
)

set BK=.claude\backup-before-decision-log
if not exist "%BK%" mkdir "%BK%"
copy /Y ".claude\hooks\bash_guard.py" "%BK%\" >nul
copy /Y ".claude\hooks\protect_sensitive_files.py" "%BK%\" >nul
copy /Y ".claude\settings.json" "%BK%\" >nul
echo Backed up current hooks and settings to %BK%

set P=docs\patches\agent-decision-log
copy /Y "%P%\_decision_log.py" ".claude\hooks\" >nul
copy /Y "%P%\bash_guard.py" ".claude\hooks\" >nul
copy /Y "%P%\protect_sensitive_files.py" ".claude\hooks\" >nul
copy /Y "%P%\mcp_log.py" ".claude\hooks\" >nul
copy /Y "%P%\session_log.py" ".claude\hooks\" >nul
copy /Y "%P%\settings.merged.json" ".claude\settings.json" >nul

python -c "import json; json.load(open('.claude/settings.json')); print('settings JSON OK')"
if errorlevel 1 (
  echo ERROR: new settings are not valid JSON. Restoring your previous files.
  copy /Y "%BK%\settings.json" ".claude\settings.json" >nul
  copy /Y "%BK%\bash_guard.py" ".claude\hooks\" >nul
  copy /Y "%BK%\protect_sensitive_files.py" ".claude\hooks\" >nul
  exit /b 1
)

echo.
echo DONE. Next steps:
echo   1. Start a NEW Claude Code conversation (or run "Developer: Reload Window" in VS Code).
echo   2. Ask Claude to run a command that uses curl; it should be blocked.
echo   3. Run: uv run sentinel agentlog verify     (expect: chain OK, 2 entries)
echo To undo: copy the three files from %BK% back into .claude\hooks and .claude\settings.json
endlocal
