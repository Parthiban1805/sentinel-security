"""sentinel init: config rendering, repo detection, .gitignore, token handling, flows, validation."""

import subprocess
import sys
from pathlib import Path

import pytest

from sentinel import config, onboarding, runner
from sentinel.cli import main
from sentinel.simulation.fakes import fake_google_key

FAKE_TOKEN = "github_pat_" + "Q7w3E9r1T5" * 6  # built at runtime, obviously fake


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


def repo_with_remote(tmp_path: Path, url: str | None, name: str = "my repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    if url:
        git(repo, "remote", "add", "origin", url)
    return repo


class Io:
    """Collects output; scripted answers for ask() and ask_secret()."""

    def __init__(self, answers: list[str] | None = None, secret: str = "") -> None:
        self.lines: list[str] = []
        self.answers = list(answers or [])
        self.secret = secret
        self.questions: list[str] = []

    def out(self, line: str) -> None:
        self.lines.append(line)

    def ask(self, question: str, default: str) -> str:
        self.questions.append(question)
        return self.answers.pop(0) if self.answers else default

    def ask_secret(self, question: str) -> str:
        self.questions.append(question)
        return self.secret

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def options(tmp_path: Path, **kw: object) -> onboarding.InitOptions:
    defaults: dict[str, object] = {
        "config_path": tmp_path / "sentinel.toml",
        "home": tmp_path / ".sentinel",
        "root": tmp_path,
    }
    return onboarding.InitOptions(**{**defaults, **kw})  # type: ignore[arg-type]


# pieces -----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "https://github.com/Parthiban1805/sentinel-security.git",
            "Parthiban1805/sentinel-security",
        ),
        ("https://github.com/o/r", "o/r"),
        ("git@github.com:owner/some.repo.git", "owner/some.repo"),
        ("https://gitlab.com/o/r.git", None),
        (None, None),
    ],
)
def test_detect_github_repo(tmp_path: Path, url: str | None, expected: str | None) -> None:
    assert onboarding.detect_github_repo(repo_with_remote(tmp_path, url)) == expected


def test_detect_on_non_repo_folder_is_none(tmp_path: Path) -> None:
    assert onboarding.detect_github_repo(tmp_path) is None


def test_rendered_config_round_trips_even_with_awkward_paths(tmp_path: Path) -> None:
    awkward = ['P:/dev/my "quoted" repo', "C:/with space/and\\backslash"]
    text = onboarding.render_config(awkward, ["o/r"], True, ["demo-project"])
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text(text, encoding="utf-8")
    loaded = config.load(cfg)
    assert list(loaded.scan_paths) == awkward and loaded.github_repos == ("o/r",)
    assert loaded.github_user_keys is True and loaded.gcp_projects == ("demo-project",)


def test_config_without_gcp_has_no_gcp_section() -> None:
    assert "[gcp]" not in onboarding.render_config(["."], [], False, [])


def test_ensure_gitignore_creates_appends_and_is_idempotent(tmp_path: Path) -> None:
    assert onboarding.ensure_gitignore(tmp_path) == [".sentinel/", "sentinel.toml"]
    assert onboarding.ensure_gitignore(tmp_path) == []
    other = tmp_path / "x"
    other.mkdir()
    (other / ".gitignore").write_text("node_modules/")  # no trailing newline
    assert onboarding.ensure_gitignore(other) == [".sentinel/", "sentinel.toml"]
    lines = (other / ".gitignore").read_text().splitlines()
    assert lines[0] == "node_modules/" and ".sentinel/" in lines


def test_write_token_validates_and_restricts(tmp_path: Path) -> None:
    path = onboarding.write_token(tmp_path / "h", f"  {FAKE_TOKEN}\n")
    assert path.read_text() == FAKE_TOKEN
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o077 == 0
    for bad in ("", "short", "has space " * 5, "x" * 300):
        with pytest.raises(ValueError) as exc:
            onboarding.write_token(tmp_path / "h", bad)
        assert bad.strip() not in str(exc.value) or not bad.strip()


def test_config_validation_rejects_path_tricks(tmp_path: Path) -> None:
    for bad in ("a/b/../../user/keys", "no-slash", "a/b/c", "o/r?x=1", "o/ r"):
        with pytest.raises(ValueError):
            config.validate_repo(bad)
    for bad in ("Bad_Project", "a/b", "9start", "x"):
        with pytest.raises(ValueError):
            config.validate_project(bad)
    cfg = tmp_path / "c.toml"
    cfg.write_text('[github]\nrepos = ["a/b/../../user/keys"]\n')
    with pytest.raises(ValueError):
        config.load(cfg)


# flows ---------------------------------------------------------------------------------------------
def test_non_interactive_init_detects_repo_and_builds_everything(tmp_path: Path) -> None:
    repo = repo_with_remote(tmp_path, "https://github.com/acme/widgets.git", "work tree")
    io = Io()
    code = onboarding.run_init(
        options(tmp_path, scan_paths=[str(repo)]), io.out, io.ask, io.ask_secret
    )
    assert code == 0 and io.questions == []  # never asked anything
    loaded = config.load(tmp_path / "sentinel.toml")
    assert loaded.github_repos == ("acme/widgets",) and loaded.github_user_keys is False
    assert (tmp_path / ".sentinel" / "fingerprint.key").exists()
    assert ".sentinel/" in (tmp_path / ".gitignore").read_text()
    assert "Health check" in io.text and "Next: uv run sentinel run" in io.text
    assert runner.GITHUB_TOKEN_ENV in io.text  # tells the user where the token goes


def test_existing_config_is_not_overwritten_without_force(tmp_path: Path) -> None:
    (tmp_path / "sentinel.toml").write_text("# mine\n")
    io = Io()
    assert onboarding.run_init(options(tmp_path), io.out, io.ask, io.ask_secret) == 1
    assert (tmp_path / "sentinel.toml").read_text() == "# mine\n"
    assert onboarding.run_init(options(tmp_path, force=True), io.out, io.ask, io.ask_secret) == 0
    assert (tmp_path / "sentinel.toml.bak").read_text() == "# mine\n"


def test_interactive_flow_with_hidden_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = repo_with_remote(tmp_path, "https://github.com/acme/widgets.git")
    io = Io(answers=[str(repo), "acme/widgets, acme/other", "y"], secret=FAKE_TOKEN)
    code = onboarding.run_init(
        options(tmp_path, interactive=True, store_token=True), io.out, io.ask, io.ask_secret
    )
    assert code == 0
    loaded = config.load(tmp_path / "sentinel.toml")
    assert loaded.github_repos == ("acme/widgets", "acme/other") and loaded.github_user_keys is True
    token_file = tmp_path / ".sentinel" / runner.GITHUB_TOKEN_FILE
    assert token_file.read_text() == FAKE_TOKEN
    assert FAKE_TOKEN not in io.text and FAKE_TOKEN not in capsys.readouterr().out  # never shown
    assert "Git SSH keys: read" in io.text  # permission hint appears because SSH keys were chosen


def test_malformed_token_is_not_saved_or_echoed(tmp_path: Path) -> None:
    junk = "not a token with spaces"
    io = Io(answers=[str(tmp_path), "o/r", "n"], secret=junk)
    onboarding.run_init(
        options(tmp_path, interactive=True, store_token=True), io.out, io.ask, io.ask_secret
    )
    assert not (tmp_path / ".sentinel" / runner.GITHUB_TOKEN_FILE).exists()
    assert "token NOT saved" in io.text and junk not in io.text


def test_pasted_credential_cannot_end_up_in_the_config(tmp_path: Path) -> None:
    key = fake_google_key()
    io = Io(answers=[str(tmp_path), key, "n"])  # a key pasted into the repository question
    code = onboarding.run_init(options(tmp_path, interactive=True), io.out, io.ask, io.ask_secret)
    assert code == 1 and not (tmp_path / "sentinel.toml").exists()


def test_invalid_repo_and_project_are_rejected_before_writing(tmp_path: Path) -> None:
    io = Io()
    assert (
        onboarding.run_init(
            options(tmp_path, github_repos=["bad repo"]), io.out, io.ask, io.ask_secret
        )
        == 1
    )
    assert (
        onboarding.run_init(
            options(tmp_path, gcp_projects=["Bad_ID"]), io.out, io.ask, io.ask_secret
        )
        == 1
    )
    assert not (tmp_path / "sentinel.toml").exists()


def test_cli_init_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = repo_with_remote(tmp_path, "https://github.com/acme/widgets.git", "proj")
    monkeypatch.chdir(tmp_path)
    code = main(["--home", str(tmp_path / ".sentinel"), "init", "--no-prompt",
                 "--scan-path", str(repo), "--config", str(tmp_path / "sentinel.toml")])  # fmt: skip
    out = capsys.readouterr().out
    assert code == 0 and "wrote" in out and "acme/widgets" in out
    assert main(
        [
            "--home",
            str(tmp_path / ".sentinel"),
            "doctor",
            "--config",
            str(tmp_path / "sentinel.toml"),
        ]
    ) in (0, 1)
