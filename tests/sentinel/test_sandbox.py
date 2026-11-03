"""v0.7b Docker sandbox (ADR-0017): scratch copy without secrets, hardened docker run, no write-back,
output and time caps, gateway rules and strict mode. Unit tests use a fake docker runner; the live
test runs only when SENTINEL_SANDBOX_IMAGE names a pinned image on this machine and Docker runs."""

import io
import os
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_gateway import POLICY, decide

from sentinel import config, sandbox
from sentinel.cli import main

IMAGE = "python:3.11-slim@sha256:" + "a" * 64


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    files = {
        "app.py": "print('hello')\n",
        "docs/readme.md": "# x\n",
        ".env": "FAKE_VALUE=not-a-real-secret\n",
        ".env.example": "FAKE_VALUE=\n",
        "sub/dir/.env.local": "FAKE=1\n",
        "certs/server.key": "fake\n",
        ".sentinel/state.json": "{}\n",
        ".docker/config.json": "{}\n",
        "config/service-account-prod.json": "{}\n",
        "android/google-services.json": "{}\n",
        ".npmrc": "fake\n",
        ".mcp.json": "{}\n",
        "sentinel.toml": "[sandbox]\n",
        "secrets/x.txt": "fake\n",
    }
    for rel, text in files.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(text, encoding="utf-8")
    _git(r, "add", "-f", ".")
    (r / "untracked.txt").write_text("not tracked\n", encoding="utf-8")
    return r


# --- image, timeout and settings ------------------------------------------------------------------
@pytest.mark.parametrize(
    "image", ["python:3.11-slim", "python@sha256:abc", "", "x@sha256:" + "A" * 64]
)
def test_image_must_be_pinned_by_digest(image: str) -> None:
    with pytest.raises(sandbox.SandboxError, match="pinned by digest"):
        sandbox.check_image(image)


def test_pinned_image_and_timeout_bounds() -> None:
    assert sandbox.check_image(IMAGE) == IMAGE
    assert sandbox.check_timeout(60) == 60
    for bad in (0, 3601, -5):
        with pytest.raises(sandbox.SandboxError, match="timeout"):
            sandbox.check_timeout(bad)


def test_sandbox_settings_are_validated(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text(f'[sandbox]\nimage = "{IMAGE}"\nmemory = "2g"\n', encoding="utf-8")
    assert config.load(cfg).sandbox.memory == "2g"
    cfg.write_text('[sandbox]\nmemory = "lots"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="memory"):
        config.load(cfg)


# --- scratch copy ---------------------------------------------------------------------------------
def test_scratch_copy_has_tracked_files_but_no_secrets(repo: Path) -> None:
    scratch, copied, skipped = sandbox.make_scratch(repo, sandbox.tracked_files(repo))
    try:
        present = {p.relative_to(scratch).as_posix() for p in scratch.rglob("*") if p.is_file()}
        assert present == {"app.py", "docs/readme.md", ".env.example"}
        assert copied == 3
        for secret in (".env", "sub/dir/.env.local", "certs/server.key", ".docker/config.json",
                       "android/google-services.json", ".npmrc", "sentinel.toml"):  # fmt: skip
            assert secret in skipped, secret
    finally:
        shutil.rmtree(scratch)


def test_hardlinked_files_are_not_copied(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside the repo\n", encoding="utf-8")
    try:
        os.link(outside, repo / "linked.txt")
    except OSError:
        pytest.skip("hard links are not available here")
    scratch, _copied, skipped = sandbox.make_scratch(repo, ["linked.txt", "app.py"])
    try:
        assert "linked.txt" in skipped and not (scratch / "linked.txt").exists()
    finally:
        shutil.rmtree(scratch)


# Sample paths for every gateway file rule that blocks reads ("all"): the sandbox must leave each out.
PF_ALL_SAMPLES = {
    "PF-01": ".env", "PF-02": "a/server.pem", "PF-03": "id_ed25519", "PF-04": ".ssh/config",
    "PF-05": ".aws/credentials", "PF-06": ".azure/x", "PF-07": ".kube/config",
    "PF-08": ".config/gcloud/x", "PF-09": ".docker/config.json", "PF-10": ".netrc",
    "PF-11": ".git-credentials", "PF-12": "secrets/a", "PF-13": "credentials.json",
    "PF-14": "service-account.json", "PF-17": ".sentinel/x", "PF-19": ".claude.json",
    "PF-22": ".npmrc",
}  # fmt: skip


def test_every_gateway_read_rule_is_also_left_out_of_the_sandbox() -> None:
    all_rules = [r[0] for r in POLICY.FILE_RULES if r[3] == "all"]
    assert set(all_rules) == set(PF_ALL_SAMPLES), "add a sample for each new read-blocking rule"
    for rule, sample in PF_ALL_SAMPLES.items():
        assert sandbox.EXCLUDED.search(sample), (rule, sample)


# --- the docker command ---------------------------------------------------------------------------
def test_docker_args_carry_every_hardening_flag(tmp_path: Path) -> None:
    args = sandbox.docker_args(IMAGE, tmp_path, ["python", "app.py"], sandbox.Limits(), "n1")
    joined = " ".join(args)
    for flag in (
        "--pull never",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pids-limit 256",
        "--memory 1g",
        "--memory-swap 1g",
        "--ipc none",
        "--user 65534:65534",
        "--ulimit nofile=1024:1024",
        "--rm",
    ):
        assert flag in joined, flag
    assert f"--ulimit fsize={sandbox.MAX_WRITE_BYTES}" in joined
    assert f"type=bind,source={tmp_path},target=/work" in joined
    assert "docker.sock" not in joined and "--privileged" not in joined
    assert args[-3:] == [IMAGE, "python", "app.py"]  # no shell wrapping


class FakeDocker:
    def __init__(self, code: int = 0, timed_out: bool = False, cut: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.code, self.timed_out, self.cut = code, timed_out, cut
        self.killed = False

    def __call__(
        self, args: list[str], env: dict[str, str], timeout_s: int, kill: Callable[[], None]
    ) -> tuple[int, str, str, bool, bool]:
        mount = next(a for a in args if a.startswith("type=bind"))
        scratch = Path(mount.split("source=")[1].split(",target=")[0])
        files = sorted(p.relative_to(scratch).as_posix() for p in scratch.rglob("*") if p.is_file())
        self.calls.append({"args": args, "env": env, "timeout": timeout_s, "files": files})
        (scratch / "app.py").write_text("changed inside the sandbox\n", encoding="utf-8")
        if self.timed_out or self.cut:
            self.killed = True
        return (124 if self.timed_out else self.code), "out\n", "", self.timed_out, self.cut


def test_run_changes_nothing_in_the_repo_and_passes_no_docker_or_secret_env(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOKEN_FOR_TEST", "should-not-reach-docker")
    monkeypatch.setenv("DOCKER_HOST", "tcp://elsewhere.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "elsewhere")
    fake = FakeDocker()
    result = sandbox.run(repo, IMAGE, ["python", "app.py"], runner=fake)
    assert result.exit_code == 0 and result.stdout == "out\n" and result.scratch is None
    assert (repo / "app.py").read_text(encoding="utf-8") == "print('hello')\n"  # no write-back
    env = fake.calls[0]["env"]
    assert "FAKE_TOKEN_FOR_TEST" not in env and "DOCKER_HOST" not in env
    assert "DOCKER_CONTEXT" not in env
    assert ".env" not in fake.calls[0]["files"]


def test_scratch_is_removed_unless_kept(repo: Path) -> None:
    kept = sandbox.run(repo, IMAGE, ["true"], keep=True, runner=FakeDocker())
    assert kept.scratch is not None and kept.scratch.is_dir()
    assert (kept.scratch / "app.py").read_text(encoding="utf-8").startswith("changed")
    shutil.rmtree(kept.scratch)


def test_timeout_and_output_cap_are_reported(repo: Path) -> None:
    timed = sandbox.run(repo, IMAGE, ["sleep", "999"], runner=FakeDocker(timed_out=True))
    assert timed.timed_out and timed.exit_code == 124 and "timed out" in timed.stderr
    cut = sandbox.run(repo, IMAGE, ["yes"], runner=FakeDocker(cut=True))
    assert cut.output_cut and "was stopped" in cut.stderr


def test_output_reader_stops_at_the_cap_and_calls_kill() -> None:
    stream = io.BytesIO(b"x" * (sandbox.MAX_OUTPUT_BYTES + 5000))
    sink, cut, kills = bytearray(), threading.Event(), []
    sandbox._read_capped(stream, sink, cut, lambda: kills.append(1))
    assert len(sink) == sandbox.MAX_OUTPUT_BYTES and cut.is_set() and kills == [1]


def test_bad_inputs_run_nothing(repo: Path) -> None:
    fake = FakeDocker()
    with pytest.raises(sandbox.SandboxError):
        sandbox.run(repo, "python:latest", ["true"], runner=fake)
    with pytest.raises(sandbox.SandboxError, match="timeout"):
        sandbox.run(repo, IMAGE, ["true"], sandbox.Limits(timeout_s=999999), runner=fake)
    assert fake.calls == []


def test_sandbox_run_has_no_config_option(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["sandbox", "run", "--config", "other.toml", "--", "true"])


# --- gateway (patch files) ------------------------------------------------------------------------
def test_sandboxed_one_liners_still_ask(tmp_path: Path) -> None:
    """No exemption: a shell-level name check cannot prove the sandbox runs (security review)."""
    for command in (
        'sentinel sandbox run -- python -c "print(1)"',
        "uv run sentinel sandbox run -- node -e 1",
        'sentinel(){ shift 3; "$@"; }; sentinel sandbox run -- python -c 1',  # function trick
    ):
        assert decide(tmp_path, "Bash", command=command).decision == "ask", command
    assert decide(tmp_path, "Bash", command="sentinel sandbox run -- pytest -q").decision == "allow"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("docker run --privileged alpine", "deny"),
        ("docker run -v C:/Users:/u alpine", "deny"),
        ("docker run --mount type=bind,src=C:/,dst=/h alpine", "deny"),
        ("docker run --network host alpine", "deny"),
        ("podman run -v /:/h alpine", "deny"),
        ("docker context use other", "deny"),
        ("DOCKER_HOST=tcp://x sentinel sandbox run -- true", "deny"),
        ("docker ps", "ask"),
        ("docker image inspect python", "ask"),
        ("git stash --all", "deny"),
        ("git stash -a", "deny"),
        ("git stash", "allow"),
        ("ln notes.txt other.txt", "ask"),
        ("echo x >> ~/.bashrc", "deny"),
        ("cp other.toml sentinel.toml", "deny"),
    ],
)
def test_gateway_rules_from_the_sandbox_review(tmp_path: Path, command: str, expected: str) -> None:
    assert decide(tmp_path, "Bash", command=command).decision == expected, command


def test_config_profiles_and_token_files_are_protected(tmp_path: Path) -> None:
    assert decide(tmp_path, "Write", file_path="sentinel.toml").decision == "deny"
    assert decide(tmp_path, "Read", file_path="sentinel.toml").decision == "allow"
    assert decide(tmp_path, "Edit", file_path="~/.bashrc").decision == "deny"
    assert decide(tmp_path, "Read", file_path="app/google-services.json").decision == "deny"
    assert decide(tmp_path, "Read", file_path=".npmrc").decision == "deny"


def test_strict_mode_asks_for_code_outside_the_sandbox(tmp_path: Path) -> None:
    assert decide(tmp_path, "Bash", command="python app.py").decision == "allow"
    sandbox.strict_on(tmp_path)
    for command in (
        "python app.py", "uv run pytest -q", "node build.js", "pytest", "bash x.sh", "./x.sh",
        "x.bat", "make test", "npm test", "uv run x.py", "uv run ruff check .",
        "sentinel sandbox run -- true; python app.py",  # a second command is not sandboxed
        "uv run --project=C:/tmp/p sentinel sandbox run -- true",  # options pick another project
    ):  # fmt: skip
        d = decide(tmp_path, "Bash", command=command)
        assert (d.decision, d.rule) == ("ask", "BG-23"), command
    for command in ("sentinel sandbox run -- pytest", "uv run sentinel sandbox run -- make",
                    "git status", "ls -la"):  # fmt: skip
        assert decide(tmp_path, "Bash", command=command).decision == "allow", command


def test_strict_mode_off_needs_a_person_and_on_warns_about_the_folder(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "state"
    assert main(["--home", str(home), "sandbox", "strict", "on"]) == 0
    assert "will NOT see it" in capsys.readouterr().err
    assert main(["--home", str(home), "sandbox", "strict", "off"]) == 1
    assert "interactive terminal" in capsys.readouterr().err
    assert sandbox.strict_status(home)


# --- live Docker (skipped unless configured) ------------------------------------------------------
LIVE_IMAGE = os.environ.get("SENTINEL_SANDBOX_IMAGE", "")


def _live_ready() -> bool:
    if not LIVE_IMAGE:
        return False
    try:
        return sandbox.docker_status(LIVE_IMAGE) == []
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(not _live_ready(), reason="set SENTINEL_SANDBOX_IMAGE and start Docker")
def test_live_sandbox_has_no_network_no_secrets_and_no_root(repo: Path) -> None:
    probe = (
        "import os, socket\n"
        "print('uid', os.getuid())\n"
        "print('env_file', os.path.exists('.env'))\n"
        "print('sock', os.path.exists('/var/run/docker.sock'))\n"
        "try:\n"
        "    socket.create_connection(('192.0.2.1', 80), 3)\n"  # TEST-NET-1: never routable
        "    print('net', 'open')\n"
        "except OSError:\n"
        "    print('net', 'blocked')\n"
    )
    result = sandbox.run(repo, LIVE_IMAGE, ["python", "-c", probe], sandbox.Limits(timeout_s=120))
    assert result.exit_code == 0, result.stderr
    assert "uid 65534" in result.stdout
    assert "env_file False" in result.stdout
    assert "sock False" in result.stdout
    assert "net blocked" in result.stdout
