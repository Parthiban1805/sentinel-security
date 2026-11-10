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

`--allow-net` (ADR-0026) instead puts the container on a per-run INTERNAL Docker network whose only
other member is an egress proxy (sentinel/egressproxy.py, run from the same pinned image). The proxy
alone is also on a per-run outbound network, and lets through only the hosts in [sandbox.egress].
Each refusal becomes an `egress_anomaly` event; refused host names are stored as a suffix and a
hash, never whole (a host name the sandbox asked for can carry data).
"""

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel import contextfirewall, egressproxy
from sentinel.events.schema import make_event
from sentinel.inventory.agents import agent_asset_id

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
PROXY_ALIAS = "egress-proxy"
PROXY_URL = f"http://{PROXY_ALIAS}:{egressproxy.PROXY_PORT}"
# Upstream for Docker's embedded DNS in a networked sandbox: TEST-NET-1, never routable, so names
# other than the proxy's do not resolve from inside (the proxy resolves what it lets through).
SANDBOX_DNS = "192.0.2.1"
READY_TRIES, READY_WAIT_S = 40, 0.25
MAX_EGRESS_EVENTS = 50  # per run; more refusals are counted in one summary event

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
    egress: "EgressReport | None" = None
    run_name: str = ""


@dataclass(frozen=True)
class Egress:
    """[sandbox.egress] in sentinel.toml: `allow` (HTTPS hosts) and `http` (plain HTTP rules)."""

    allow: tuple[str, ...] = ()
    http: tuple[str, ...] = ()

    def known_domains(self) -> set[str]:
        """Last two labels of every allowed host: refused names under these are shown as is."""
        rules = egressproxy.Rules.from_config(self.config())
        hosts = [r.pattern.removeprefix("*.") for r in rules.allow] + [r.host for r in rules.http]
        return {".".join(h.split(".")[-2:]) for h in hosts}

    def config(self) -> dict[str, list[str]]:
        cfg = {"allow": list(self.allow), "http": list(self.http)}
        egressproxy.Rules.from_config(cfg)  # raises ValueError on a bad rule
        return cfg


@dataclass
class EgressReport:
    """What the proxy saw. Refusals hold only safe fields (see `_safe_refusal`)."""

    allowed: int = 0
    refused: list[dict[str, Any]] = field(default_factory=list)
    errors: int = 0
    log_cut: bool = False
    cleanup_ok: bool = True


@dataclass(frozen=True)
class _ProxySession:
    net_in: str
    net_out: str
    proxy: str
    folder: Path


# (args, env, timeout_s, kill) -> (exit code, stdout, stderr, timed_out, output_cut)
Runner = Callable[
    [list[str], dict[str, str], int, Callable[[], None]], tuple[int, str, str, bool, bool]
]
# One short docker CLI call: args -> (exit code, stdout, stderr)
DockerCmd = Callable[[list[str]], tuple[int, str, str]]


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
    image: str,
    scratch: Path,
    command: list[str],
    limits: Limits,
    name: str,
    *,
    network: str = "none",
) -> list[str]:
    """The exact `docker run` argument list (tested: every hardening flag is present).
    `network` other than "none" is the per-run internal network of the egress proxy."""
    net: list[str] = ["--network", network]
    if network != "none":
        net += ["--dns", SANDBOX_DNS]
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            net += ["--env", f"{var}={PROXY_URL}"]
        net += ["--env", "NO_PROXY=", "--env", "no_proxy="]
    return [
        "docker", "run", "--rm",
        "--pull", "never",
        "--name", name,
        "--label", LABEL,
        *net,
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


def _docker_cmd(env: dict[str, str]) -> DockerCmd:
    def call(args: list[str]) -> tuple[int, str, str]:
        try:
            p = subprocess.run(  # noqa: S603 - fixed docker argument lists built here
                args, capture_output=True, check=False, timeout=60, env=env,
                encoding="utf-8", errors="replace",
            )  # fmt: skip
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, "", type(exc).__name__
        return p.returncode, p.stdout or "", p.stderr or ""

    return call


# --- egress proxy (ADR-0026) ----------------------------------------------------------------------
def proxy_args(image: str, session: _ProxySession) -> list[str]:
    """`docker run` for the proxy: same hardening as the sandbox, on the outbound network only
    (it joins the internal one next, under the alias the sandbox's proxy variables name)."""
    return [
        "docker", "run", "-d",
        "--pull", "never",
        "--name", session.proxy,
        "--label", LABEL,
        "--network", session.net_out,
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--ulimit", "nofile=1024:1024",
        "--memory", "256m",
        "--memory-swap", "256m",
        "--cpus", "1",
        "--ipc", "none",
        "--user", "65534:65534",
        "--hostname", PROXY_ALIAS,
        "--mount", f"type=bind,source={session.folder},target=/proxy,readonly",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint", "",
        check_image(image),
        "python3", "-I", "/proxy/egressproxy.py", "/proxy/config.json",
    ]  # fmt: skip


def _proxy_lines(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _must(result: tuple[int, str, str], what: str) -> None:
    if result[0] != 0:
        raise SandboxError(f"cannot {what} (docker exit {result[0]})")


def _start_proxy(image: str, egress: Egress, name: str, docker: DockerCmd) -> _ProxySession:
    cfg = egress.config()
    folder = Path(tempfile.mkdtemp(prefix="sentinel-egress-"))
    session = _ProxySession(f"{name}-in", f"{name}-out", f"{name}-proxy", folder)
    try:
        if "," in str(folder):
            raise SandboxError(
                "the temp folder path contains a comma, which Docker mounts cannot use"
            )
        shutil.copyfile(Path(egressproxy.__file__), folder / "egressproxy.py")
        (folder / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        # The proxy runs as uid 65534; it needs to read these two files (they hold no secrets).
        folder.chmod(0o755)
        for f in folder.iterdir():
            f.chmod(0o644)
        _must(docker(["docker", "network", "create", "--internal", "--label", LABEL,
                      session.net_in]), "create the sandbox's internal network")  # fmt: skip
        _must(docker(["docker", "network", "create", "--label", LABEL, session.net_out]),
              "create the proxy's outbound network")  # fmt: skip
        _must(docker(proxy_args(image, session)), "start the egress proxy")
        _must(docker(["docker", "network", "connect", "--alias", PROXY_ALIAS, session.net_in,
                      session.proxy]), "connect the egress proxy")  # fmt: skip
        for _ in range(READY_TRIES):
            lines = _proxy_lines(docker(["docker", "logs", session.proxy])[1])
            if any(x.get("ev") == "fatal" for x in lines):
                raise SandboxError("the egress proxy refused its configuration")
            if any(x.get("ev") == "ready" for x in lines):
                return session
            time.sleep(READY_WAIT_S)
        raise SandboxError("the egress proxy did not start (the sandbox image needs python3)")
    except BaseException:
        _stop_proxy(session, docker)
        raise


def _host_suffix(host: str, known: Collection[str]) -> str:
    """What is kept of a refused name (rule 1: a name the sandbox asked for can carry data in any
    label it chose). Under a domain the owner allowed: that domain. Otherwise only the last
    label and a hash of the one before it, e.g. `h-1a2b3c4d.com`."""
    labels = [x for x in host.lower().rstrip(".").split(".") if x]
    if len(labels) < 2:
        return "(no domain)"
    suffix = ".".join(labels[-2:])
    if suffix in known and not sum(contextfirewall.scan(suffix)["counts"].values()):
        return suffix
    tld = labels[-1] if len(labels[-1]) <= 24 and labels[-1].isalpha() else "?"
    return f"h-{hashlib.sha256(labels[-2].encode()).hexdigest()[:8]}.{tld}"


def _real_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _safe_refusal(entry: dict[str, Any], known: Collection[str] = ()) -> dict[str, Any]:
    host = str(entry.get("host", ""))[:255]
    reason = str(entry.get("reason", "unknown"))[:40]
    port = entry.get("port") if isinstance(entry.get("port"), int) else 0
    method = str(entry.get("method", ""))[:10]
    target = ""
    if reason in ("metadata_address", "internal_address"):
        target = reason.split("_")[0]
    safe: dict[str, Any] = {"reason": reason, "port": port, "method": method, "target": target,
                            "host_fp": hashlib.sha256(host.encode()).hexdigest()[:12]}  # fmt: skip
    if reason == "ip_literal" and _real_ip(host):
        # Only an address that parses is kept, and only when it is internal or metadata.
        blocked = egressproxy.blocked_address(host)
        safe["target"] = blocked.split("_")[0] if blocked else "public"
        safe["host"] = host if blocked else "[public address]"
    else:
        safe["host"] = _host_suffix(host, known) if host else ""
    return safe


def _stop_proxy(
    session: _ProxySession, docker: DockerCmd, known: Collection[str] = ()
) -> EgressReport:
    report = EgressReport()
    code, logs, _ = docker(["docker", "logs", session.proxy])
    if code == 0:
        for x in _proxy_lines(logs):
            ev = x.get("ev")
            if ev == "allow":
                report.allowed += 1
            elif ev == "refuse":
                report.refused.append(_safe_refusal(x, known))
            elif ev == "error":
                report.errors += 1
            elif ev == "log_cut":
                report.log_cut = True
    steps = [
        ["docker", "rm", "-f", session.proxy],
        ["docker", "network", "rm", session.net_in],
        ["docker", "network", "rm", session.net_out],
    ]
    for step in steps:
        if docker(step)[0] != 0:
            report.cleanup_ok = False
    shutil.rmtree(session.folder, ignore_errors=True)
    return report


def _severity(refusal: dict[str, Any]) -> str:
    return {"metadata": "high", "internal": "medium"}.get(refusal.get("target", ""), "low")


def egress_events(result: Result, workspace: Path, now: datetime) -> list[dict[str, Any]]:
    """One `egress_anomaly` per refusal (up to MAX_EGRESS_EVENTS), plus one summary for the rest
    and one when the proxy's log was cut. Observed by the proxy: confidence high. What the code
    meant by it is not known (a hypothesis for the incident, never a fact in the event)."""
    report = result.egress
    if report is None:
        return []
    asset = agent_asset_id(workspace)
    rank = ["low", "medium", "high"]
    refused = sorted(report.refused, key=lambda r: -rank.index(_severity(r)))  # stable
    events = []
    for i, r in enumerate(refused[:MAX_EGRESS_EVENTS]):
        events.append(make_event(
            event_type="egress_anomaly", source="sandbox_proxy", asset_id=asset, time=now,
            severity=_severity(r), confidence="high",
            evidence_ref=f"sandbox:{result.run_name}:refusal:{i}",
            event_id=f"egress:{result.run_name}:{i}",
            attributes={**r, "sandbox_run": result.run_name},
        ))  # fmt: skip
    extra = len(report.refused) - MAX_EGRESS_EVENTS
    if extra > 0 or report.log_cut:
        events.append(make_event(
            event_type="egress_anomaly", source="sandbox_proxy", asset_id=asset, time=now,
            # A cut log hid what came after it: never report that as low.
            severity=max([_severity(r) for r in refused[MAX_EGRESS_EVENTS:]]
                         + (["medium"] if report.log_cut else []), key=rank.index, default="low"),
            confidence="high", evidence_ref=f"sandbox:{result.run_name}:summary",
            event_id=f"egress:{result.run_name}:summary",
            attributes={"reason": "many_refusals", "more_refusals": max(extra, 0),
                        "log_cut": report.log_cut, "sandbox_run": result.run_name},
        ))  # fmt: skip
    return events


def run(
    repo: Path,
    image: str,
    command: list[str],
    limits: Limits | None = None,
    *,
    keep: bool = False,
    runner: Runner | None = None,
    egress: Egress | None = None,
    docker: DockerCmd | None = None,
) -> Result:
    limits = limits or Limits()
    if not command:
        raise SandboxError("nothing to run: sentinel sandbox run -- <command>")
    check_image(image)
    check_timeout(limits.timeout_s)
    if egress is not None:
        if not egress.allow and not egress.http:
            raise SandboxError("--allow-net needs [sandbox.egress] allow or http in sentinel.toml")
        try:
            egress.config()
        except ValueError as exc:
            raise SandboxError(f"[sandbox.egress]: {exc}") from None
    if runner is None and shutil.which("docker") is None:
        raise SandboxError("docker is not installed or not on PATH")
    name = "sentinel-sbx-" + uuid.uuid4().hex[:12]
    env = _docker_env()
    docker = docker or _docker_cmd(env)
    kill = _kill_container(name, env)
    scratch, copied, skipped = make_scratch(repo, tracked_files(repo))
    session: _ProxySession | None = None
    report: EgressReport | None = None
    try:
        if egress is not None:
            session = _start_proxy(image, egress, name, docker)
        network = session.net_in if session else "none"
        try:
            code, out, err, timed_out, cut = (runner or _popen_runner)(
                docker_args(image, scratch, command, limits, name, network=network),
                env, limits.timeout_s, kill,
            )  # fmt: skip
        except OSError as exc:
            raise SandboxError(f"cannot start docker ({type(exc).__name__})") from None
        except BaseException:
            kill()  # Ctrl+C or an unexpected error: do not leave the container running
            raise
    finally:
        if session is not None:
            report = _stop_proxy(session, docker, egress.known_domains() if egress else set())
        if not keep:
            shutil.rmtree(scratch, ignore_errors=True)
    if timed_out:
        err += f"\nsandbox timed out after {limits.timeout_s} s and was stopped"
    if cut:
        err += f"\nsandbox output passed {MAX_OUTPUT_BYTES} bytes; the container was stopped"
    if report is not None and not report.cleanup_ok:
        err += (
            "\nsandbox: could not remove every egress resource; "
            f"run: docker ps -a --filter label={LABEL}"
        )
    return Result(code, out, err, timed_out, scratch if keep else None, copied, skipped, cut,
                  report, name)  # fmt: skip


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
