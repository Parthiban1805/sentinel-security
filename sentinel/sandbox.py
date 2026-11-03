"""Docker sandbox for agent-run code (v0.7b, ADR-0017).

`sentinel sandbox run -- <command>` runs one command in a throwaway container that has:
- no network (--network none) and never pulls an image (--pull never),
- a scratch COPY of the project's Git-tracked files, without secrets (.env, keys, Sentinel state,
  credential and token files); nothing is ever written back into the repository,
- a non-root user, a read-only root filesystem, all capabilities dropped, no-new-privileges,
  memory/CPU/process/file-size/open-file limits, a timeout, a byte cap on output, and no Docker
  socket or host environment inside.
The image must be pinned by digest and comes from sentinel.toml, which agents cannot write. No
network call is made by this module: the owner pulls the image (ADR-0017).
"""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

IMAGE_PIN = re.compile(r"[a-z0-9][a-z0-9._/-]*(:[\w.-]+)?@sha256:[0-9a-f]{64}")
STRICT_NAME = (
    "sandbox-strict"  # in the state dir: the gateway asks for code run outside the sandbox
)
LABEL = "sentinel.sandbox=1"
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 300 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024  # per stream; the container is stopped when exceeded
MAX_WRITE_BYTES = 1024 * 1024 * 1024  # largest single file a sandboxed process may write
TIMEOUT_RANGE = (1, 3600)

# Never copied into the sandbox, even when tracked by Git. Covers the gateway's protected files
# (tests check every one) plus common token and state files.
EXCLUDED = re.compile(
    r"(^|/)\.env($|[._-])(?!.*\b(example|sample|template)$)|\.env$|(^|/)\.envrc$"
    r"|\.(pem|key|p12|pfx|jks|keystore|ppk|p8|gpg|asc|tfstate|tfvars)$|\.tfstate\.backup$"
    r"|(^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*$"
    r"|(^|/)\.(ssh|aws|azure|kube|sentinel|git|gnupg|docker)(/|$)"
    r"|(^|/)\.config/gcloud(/|$)|(^|/)kubeconfig[^/]*$"
    r"|(^|/)\.(netrc|git-credentials|mcp\.json|claude\.json|npmrc|pypirc|yarnrc\.yml"
    r"|vault-token|htpasswd)$"
    r"|(^|/)\.claude/settings\.local\.json$|(^|/)sentinel\.toml$"
    r"|(^|/)secrets(/|$)"
    r"|credentials[^/]*\.json$|service[-_]?account[^/]*\.json$|client_secret[^/]*\.json$"
    r"|(^|/)google-services\.json$",
    re.IGNORECASE,
)


class SandboxError(ValueError):
    """The sandbox cannot run (Docker missing, image not pinned, project too large, ...)."""


@dataclass(frozen=True)
class Limits:
    memory: str = "1g"
    cpus: str = "2"
    pids: int = 256
    timeout_s: int = 300


@dataclass(frozen=True)
class Result:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    scratch: Path | None  # kept only when asked
    copied: int
    skipped: list[str] = field(default_factory=list)
    output_cut: bool = False


# (args, env, timeout_s, kill) -> (exit code, stdout, stderr, timed_out, output_cut)
Runner = Callable[
    [list[str], dict[str, str], int, Callable[[], None]], tuple[int, str, str, bool, bool]
]


def check_image(image: str) -> str:
    if not IMAGE_PIN.fullmatch(image or ""):
        raise SandboxError(
            "the sandbox image must be pinned by digest, for example "
            "python@sha256:<64 hex> ([sandbox] image in sentinel.toml)"
        )
    return image


def check_timeout(seconds: int) -> int:
    low, high = TIMEOUT_RANGE
    if not low <= seconds <= high:
        raise SandboxError(f"timeout must be between {low} and {high} seconds")
    return seconds


def tracked_files(repo: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxError(
            f"cannot list the project's tracked files ({type(exc).__name__})"
        ) from None
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def make_scratch(repo: Path, files: list[str]) -> tuple[Path, int, list[str]]:
    """Copy tracked files (minus secrets, links and oversized files) into a new temp folder."""
    scratch = Path(tempfile.mkdtemp(prefix="sentinel-sandbox-"))
    try:
        if "," in str(scratch):
            raise SandboxError(
                "the temp folder path contains a comma, which Docker mounts cannot use"
            )
        copied, total, skipped = 0, 0, []
        root = repo.resolve()
        for rel in files:
            if EXCLUDED.search(rel.replace("\\", "/")):
                skipped.append(rel)
                continue
            src = repo / rel
            try:
                if src.is_symlink() or not src.is_file() or not src.resolve().is_relative_to(root):
                    skipped.append(rel)
                    continue
                st = src.stat()
            except OSError:
                skipped.append(rel)
                continue
            # A hardlink can point at a file outside the repo; skip any file with several links.
            if st.st_nlink > 1 or st.st_size > MAX_FILE_BYTES:
                skipped.append(rel)
                continue
            total += st.st_size
            if total > MAX_TOTAL_BYTES:
                raise SandboxError("the project is too large to copy into the sandbox (300 MB)")
            dst = scratch / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            copied += 1
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    return scratch, copied, skipped


def docker_args(
    image: str, scratch: Path, command: list[str], limits: Limits, name: str
) -> list[str]:
    """The exact `docker run` argument list (tested: every hardening flag is present)."""
    return [
        "docker", "run", "--rm",
        "--pull", "never",
        "--name", name,
        "--label", LABEL,
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(limits.pids),
        "--memory", limits.memory,
        "--memory-swap", limits.memory,
        "--cpus", limits.cpus,
        "--ulimit", f"fsize={MAX_WRITE_BYTES}:{MAX_WRITE_BYTES}",
        "--ulimit", "nofile=1024:1024",
        "--ipc", "none",
        "--user", "65534:65534",
        "--hostname", "sandbox",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--mount", f"type=bind,source={scratch},target=/work",
        "--workdir", "/work",
        "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint", "",
        check_image(image),
        *command,
    ]  # fmt: skip


def _docker_env() -> dict[str, str]:
    """Only what the docker CLI needs to find Docker Desktop. DOCKER_HOST / DOCKER_CONTEXT /
    DOCKER_CONFIG are NOT passed: they could point the run at another engine or credentials."""
    keep = ("PATH", "SYSTEMROOT", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP",
            "TMP", "HOME", "PROGRAMDATA", "PROGRAMFILES", "WINDIR", "COMSPEC")  # fmt: skip
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


def _read_capped(
    stream: object, sink: bytearray, cut: threading.Event, on_cut: Callable[[], None]
) -> None:
    while True:
        chunk = stream.read(65536)  # type: ignore[attr-defined]
        if not chunk:
            return
        room = MAX_OUTPUT_BYTES - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
        if len(chunk) > room and not cut.is_set():
            cut.set()
            on_cut()  # stop the container; keep draining so the process can exit


def _popen_runner(
    args: list[str], env: dict[str, str], timeout_s: int, kill: Callable[[], None]
) -> tuple[int, str, str, bool, bool]:
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err, cut = bytearray(), bytearray(), threading.Event()
    readers = [
        threading.Thread(target=_read_capped, args=(proc.stdout, out, cut, kill), daemon=True),
        threading.Thread(target=_read_capped, args=(proc.stderr, err, cut, kill), daemon=True),
    ]
    for r in readers:
        r.start()
    timed_out = False
    try:
        code = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill()
        try:
            code = proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
        code = 124
    for r in readers:
        r.join(timeout=10)
    return code, _decode(out), _decode(err), timed_out, cut.is_set()


def _decode(data: bytearray) -> str:
    return bytes(data).decode("utf-8", errors="replace")


def _kill_container(name: str, env: dict[str, str]) -> Callable[[], None]:
    def kill() -> None:
        try:
            subprocess.run(
                ["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60, env=env
            )
        except (OSError, subprocess.SubprocessError):
            pass  # reported to the user by the caller as "may still be running"

    return kill


def run(
    repo: Path,
    image: str,
    command: list[str],
    limits: Limits | None = None,
    *,
    keep: bool = False,
    runner: Runner | None = None,
) -> Result:
    limits = limits or Limits()
    if not command:
        raise SandboxError("nothing to run: sentinel sandbox run -- <command>")
    check_image(image)
    check_timeout(limits.timeout_s)
    if runner is None and shutil.which("docker") is None:
        raise SandboxError("docker is not installed or not on PATH")
    scratch, copied, skipped = make_scratch(repo, tracked_files(repo))
    name = "sentinel-sbx-" + uuid.uuid4().hex[:12]
    env = _docker_env()
    kill = _kill_container(name, env)
    try:
        code, out, err, timed_out, cut = (runner or _popen_runner)(
            docker_args(image, scratch, command, limits, name), env, limits.timeout_s, kill
        )
    except OSError as exc:
        raise SandboxError(f"cannot start docker ({type(exc).__name__})") from None
    except BaseException:
        kill()  # Ctrl+C or an unexpected error: do not leave the container running
        raise
    finally:
        if not keep:
            shutil.rmtree(scratch, ignore_errors=True)
    if timed_out:
        err += f"\nsandbox timed out after {limits.timeout_s} s and was stopped"
    if cut:
        err += f"\nsandbox output passed {MAX_OUTPUT_BYTES} bytes; the container was stopped"
    return Result(code, out, err, timed_out, scratch if keep else None, copied, skipped, cut)


def docker_status(image: str) -> list[str]:
    """Readable problems that stop the sandbox, or [] when it is ready (no network involved)."""
    problems: list[str] = []
    if shutil.which("docker") is None:
        return ["docker is not installed or not on PATH"]
    env = _docker_env()
    info = subprocess.run(
        ["docker", "info", "--format", "{{.OSType}}"],
        capture_output=True, text=True, check=False, timeout=30, env=env,
    )  # fmt: skip
    if info.returncode != 0:
        return ["the Docker engine is not running (start Docker Desktop)"]
    if info.stdout.strip() != "linux":
        problems.append("Docker must run Linux containers (Docker Desktop: switch to Linux)")
    try:
        check_image(image)
    except SandboxError as exc:
        problems.append(str(exc))
        return problems
    found = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True, text=True, check=False, timeout=30, env=env,
    )  # fmt: skip
    if found.returncode != 0:
        problems.append(f"the image is not on this machine yet (run: docker pull {image})")
    return problems


# --- strict mode (read by the gateway hook) -------------------------------------------------------
def strict_on(home: Path) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / STRICT_NAME
    path.write_text("on\n", encoding="utf-8")
    return path


def strict_off(home: Path) -> bool:
    path = home / STRICT_NAME
    if not path.exists():
        return False
    path.unlink()
    return True


def strict_status(home: Path) -> bool:
    return (home / STRICT_NAME).exists()
