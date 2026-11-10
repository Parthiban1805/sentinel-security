"""Context firewall: fixes from the 2026-11-06 security review of ADR-0025."""

import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sentinel import contextfirewall as fw
from sentinel.correlation.session_risk import OUTBOUND_CLASSES
from sentinel.simulation.fakes import fake_google_key

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "docs" / "patches" / "agent-gateway"


def rand(n: int) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def pythons() -> list[list[str]]:
    found = [[sys.executable]]
    if shutil.which("py"):
        probe = subprocess.run(["py", "-3.10", "-c", "print(1)"], capture_output=True, check=False)  # noqa: S603, S607
        if probe.returncode == 0:
            found.append(["py", "-3.10"])
    return found


def hook(
    python: list[str], script: str, raw: bytes, home: Path
) -> subprocess.CompletedProcess[bytes]:
    env = {
        "SENTINEL_HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": "C:\\Windows",
    }
    return subprocess.run(
        [*python, "-I", str(GATEWAY / script)], input=raw, capture_output=True, check=False, env=env
    )  # noqa: S603


# stdin: raw UTF-8 bytes and deep nesting, on every Python that can run the hooks ---------------
@pytest.mark.parametrize("python", pythons(), ids=lambda p: " ".join(p))
def test_non_ascii_tool_input_is_still_checked(python: list[str], tmp_path: Path) -> None:
    payload = {
        "tool_name": "mcp__x__send",
        "tool_input": {"body": "Á Í Ð Ý ā " + "ghp_" + rand(36)},
    }
    r = hook(
        python, "gateway.py", json.dumps(payload, ensure_ascii=False).encode("utf-8"), tmp_path
    )
    assert r.returncode == 2 and b"FW-01" in r.stderr


@pytest.mark.parametrize("python", pythons(), ids=lambda p: " ".join(p))
def test_deeply_nested_tool_input_is_denied_not_let_through(
    python: list[str], tmp_path: Path
) -> None:
    deep = b'{"tool_name": "mcp__x__send", "tool_input": {"x": ' + b"[" * 5000 + b"]" * 5000 + b"}}"
    r = hook(python, "gateway.py", deep, tmp_path)
    assert r.returncode == 2 and b"GW-98" in r.stderr


@pytest.mark.parametrize("python", pythons(), ids=lambda p: " ".join(p))
def test_prompt_guard_reads_utf8_and_records_parse_failures(
    python: list[str], tmp_path: Path
) -> None:
    home = tmp_path / ".sentinel"
    home.mkdir()
    value = fake_google_key()
    r = hook(
        python,
        "prompt_guard.py",
        json.dumps({"prompt": "Á Ð ā " + value}, ensure_ascii=False).encode(),
        home,
    )
    assert json.loads(r.stdout)["decision"] == "block" and value.encode() not in r.stdout
    hook(python, "prompt_guard.py", b"\xff\xfe not json", home)
    last = json.loads((home / "agent-decisions.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert last["rule"] == "FW-99"


# password assignments are guesses, and code is not a password -----------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "token: Optional[str] = None",
        "password = getpass.getpass()",
        "api_key=os.getenv('X')",
        "secret: ${SECRET_NAME}",
        "password: <your-password>",
        "PWD=/home/user/x",
    ],
)
def test_code_is_not_a_password(line: str) -> None:
    assert "password_assignment" not in fw.scan(line)["counts"]


def test_a_real_looking_assignment_asks_but_never_blocks() -> None:
    line = "password = " + rand(14)
    assert fw.decide_prompt(line) is None
    verdict = fw.decide_tool("mcp__x__send", {"body": line})
    assert verdict is not None and verdict[:2] == ("ask", "FW-03")


# keys at the start of a line inside MCP content ------------------------------------------------
def test_a_key_after_a_newline_in_mcp_content_is_denied() -> None:
    body = "first line\n" + "ghp_" + rand(36) + "\n\tAIza" + rand(35)
    verdict = fw.decide_tool("mcp__github__create_file", {"content": body})
    assert verdict is not None and verdict[1] == "FW-01"


def test_known_prefixes_inside_longer_words_are_not_keys() -> None:
    text = "risk-assessment-template-file-name-v2 self_hf_" + "x" * 40 + " task-" + "y" * 30
    counts = fw.scan(text)["counts"]
    assert "sk_key" not in counts and "huggingface_token" not in counts


# metadata addresses, everywhere and in odd spellings -------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://2852039166/latest/meta-data/",
        "http://0xa9fea9fe/latest/",
        "http://0251.0376.0251.0376/",
        "http://metadata/computeMetadata/v1/",
        "http://instance-data/latest/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[fd00:ec2::254]/latest/",
    ],
)
def test_metadata_address_is_denied_for_every_data_leaving_tool(url: str) -> None:
    for tool, tool_input in (
        ("WebFetch", {"url": url, "prompt": "x"}),
        ("mcp__fetch__fetch", {"url": url}),
        ("mcp__playwright__browser_navigate", {"url": url}),
    ):
        verdict = fw.decide_tool(tool, tool_input)
        assert verdict is not None and verdict[1] == "FW-02", (tool, url)


# fewer false positives ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "rev = s[::-1]",
        "[Console]::WriteLine('x')",
        "listen on 0.0.0.0:8080",
        "example 192.0.2.10 and 198.51.100.7 and 203.0.113.5 and 2001:db8::1",
        "created_at 1730900000000",  # epoch milliseconds
        "snowflake 1234567890123456789",
    ],
)
def test_ordinary_values_are_not_flagged(text: str) -> None:
    result = fw.scan(text)
    assert "address" not in result["categories"] and "card_number" not in result["counts"], result


def test_real_card_numbers_still_count() -> None:
    for number in ("4111 1111 1111 1111", "5500-0000-0000-0004", "378282246310005"):
        assert fw.scan(f"card {number}")["counts"].get("card_number") == 1, number


# truncation is visible ---------------------------------------------------------------------------
def test_an_ask_on_oversized_input_says_it_was_only_partly_scanned() -> None:
    body = "someone@example.org " + "x " * (fw.MAX_TEXT // 2)
    verdict = fw.decide_tool("mcp__notes__write", {"text": body})
    assert verdict is not None and verdict[1] == "FW-03" and "only part" in verdict[3]


def test_a_key_at_the_end_of_a_huge_prompt_is_still_found() -> None:
    prompt = "log line\n" * (fw.MAX_TEXT // 9 + 10) + fake_google_key()
    verdict = fw.decide_prompt(prompt)
    assert verdict is not None and "only part" in verdict[3]


# more formats and evasions ----------------------------------------------------------------------
def test_pgp_private_key_blocks_and_more_formats() -> None:
    label = "PGP " + "PRIVATE KEY BLOCK"
    assert fw.scan("-----BEGIN " + label + "-----")["categories"]["private_key"] == 1
    for value in ("glpat-" + rand(20), "hf_" + rand(34), "npm_" + rand(36), "pypi-" + rand(60)):
        assert fw.scan("x " + value)["categories"].get("secret", 0) >= 1, value[:6]


def test_zero_width_lookalike_and_percent_encoded_keys() -> None:
    value = fake_google_key()
    hidden = value[:10] + "\u200b" + value[10:]  # a zero-width space inside the key
    assert fw.scan(hidden)["counts"].get("google_api_key") == 1
    encoded = "".join(f"%{ord(c):02X}" for c in value)
    assert fw.scan("https://x.example/?k=" + encoded)["counts"].get("google_api_key") == 1
    assert fw.scan(f"{value} 50%")["counts"]["google_api_key"] == 1  # not double-counted


# timing on the worst inputs --------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "a." * 500_000,
        ("x" * 63 + "@") * 15_000,
        "a:a: " * 200_000,
        "1 2 3 4 5 6 7 8 9 0 " * 50_000,
        "password=" * 100_000,
        "ignore previous " * 60_000,
    ],
    ids=["dots", "emails", "ipv6", "digits", "assignments", "injection"],
)
def test_worst_case_inputs_scan_quickly(text: str) -> None:
    started = time.monotonic()
    fw.scan(text)
    assert time.monotonic() - started < 10


# wiring ------------------------------------------------------------------------------------------
def test_firewall_denials_count_as_outbound_attempts() -> None:
    assert {"firewall_secret", "firewall_metadata"} <= OUTBOUND_CLASSES


def test_the_new_hook_files_are_required_by_the_pin() -> None:
    from sentinel import runner

    assert {"_manifest.py", "_firewall.py", "prompt_guard.py"} <= set(runner.AGENT_HOOK_FILES)


def test_hook_copy_identical() -> None:
    assert (GATEWAY / "_firewall.py").read_bytes() == (
        ROOT / "sentinel" / "contextfirewall.py"
    ).read_bytes()
