"""Local alert sinks: an append-only log (always) and a best-effort Windows toast."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time

ALERT_SEVERITIES = ("high", "critical")

# Windows PowerShell 5.1 can show WinRT toasts. Title/body arrive via environment variables, so
# incident text is never interpolated into the script (no command injection).
_TOAST_SCRIPT = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:SENTINEL_TOAST_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:SENTINEL_TOAST_BODY)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($t))
"""


def should_alert(incident: dict[str, Any]) -> bool:
    return not incident["is_test"] and incident["severity"] in ALERT_SEVERITIES


def write_log(home: Path, incident: dict[str, Any], now: Any) -> str:
    line = (
        f"{format_time(now)} {incident['severity'].upper()} {incident['id']} "
        f"{incident['rule_id']} {incident['title']}\n"
    )
    home.mkdir(parents=True, exist_ok=True)
    with (home / "alerts.log").open("a", encoding="utf-8") as handle:
        handle.write(line)
    return line.strip()


def toast(title: str, body: str) -> bool:
    if sys.platform != "win32":
        return False
    env = {**os.environ, "SENTINEL_TOAST_TITLE": title[:120], "SENTINEL_TOAST_BODY": body[:240]}
    try:
        proc = subprocess.run(  # noqa: S603 (fixed argv; data passed via env)
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _TOAST_SCRIPT],  # noqa: S607
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0
