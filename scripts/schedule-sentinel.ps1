# Creates a Windows Task Scheduler entry that runs `sentinel run` every N minutes.
# RUN THIS YOURSELF (it creates persistence on your machine; the agent must not run it).
# Review before running. Remove later with:  Unregister-ScheduledTask -TaskName "Sentinel run" -Confirm:$false
#
# The GitHub token is NOT stored in the task. Set it as a user environment variable yourself, e.g.
#   [Environment]::SetEnvironmentVariable("SENTINEL_GITHUB_TOKEN", "<token>", "User")
# Google uses Application Default Credentials (gcloud auth application-default login).

param(
    [int]$IntervalMinutes = 15,
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
)

$uv = (Get-Command uv -ErrorAction Stop).Source
$action = New-ScheduledTaskAction -Execute $uv `
    -Argument "run sentinel run --config sentinel.toml" `
    -WorkingDirectory $RepoRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable

Register-ScheduledTask -TaskName "Sentinel run" -Action $action -Trigger $trigger `
    -Settings $settings -Description "Sentinel: scan, collect, correlate, alert" | Out-Null
Write-Host "Scheduled 'Sentinel run' every $IntervalMinutes minutes in $RepoRoot"
Write-Host "Alerts: $RepoRoot\.sentinel\alerts.log (and Windows notifications if enabled)"
