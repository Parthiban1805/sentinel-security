"""GitHub collector (read-only). Destination: api.github.com (ADR-0005, sources/README.md).

Emits: ssh_key_added (diff of /user/keys snapshots), workflow_changed (commits touching
.github/workflows), release_published. Stores only ids, times, flags and fingerprints: never public
key bodies, diffs or tokens.
"""

import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from sentinel.events.refs import identity_ref
from sentinel.events.schema import format_time, make_event
from sentinel.security import fingerprint
from sentinel.sources.base import DeferredState
from sentinel.sources.http import HttpClient, HttpError
from sentinel.store.db import Store

API = "https://api.github.com"
_NETWORK = re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|nc|ncat)\b|https?://", re.IGNORECASE)
_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


def asset_id_for_repo(full_name: str) -> str:
    return "gh-" + re.sub(r"[^a-z0-9]+", "-", full_name.lower()).strip("-")


def added_line_flags(patch: str) -> dict[str, bool]:
    """Scan only added lines of a unified diff; the diff itself is never stored."""
    added = [ln[1:] for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    return {
        "adds_network": any(_NETWORK.search(ln) for ln in added),
        "adds_secret_ref": any(_SECRET_REF.search(ln) for ln in added),
    }


class GitHubCollector(DeferredState):
    name = "github"

    def __init__(self, client: HttpClient, token: str, key: bytes) -> None:
        super().__init__()
        self._client = client
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sentinel-collector",
        }
        self._key = key

    # helpers --------------------------------------------------------------------
    def _get_all(self, url: str, limit: int = 1000) -> list[Any]:
        items: list[Any] = []
        next_url: str | None = url
        while next_url and len(items) < limit:
            resp = self._client.get(next_url, self._headers)
            page = resp.json() or []
            items.extend(page)
            match = _NEXT.search(resp.headers.get("link", ""))
            next_url = match.group(1) if match else None
        return items

    def _ident(self, login: str | None) -> str | None:
        return identity_ref("user", fingerprint(login, self._key)[:12]) if login else None

    def _try(self, url: str) -> tuple[int, Any, str | None]:
        """(status, json or None, error hint). HTTP errors become data, never the body text."""
        try:
            resp = self._client.get(url, self._headers)
            return resp.status, resp.json(), None
        except HttpError as exc:
            return exc.status or 0, None, exc.hint

    def audit_inputs(self, repo: str) -> tuple[Any, Any]:
        """Raw answers for the protection audit: (repository, default-branch protection)."""
        base = f"{API}/repos/{quote(repo, safe='/')}"
        repo_probe = self._try(base)
        meta = repo_probe[1] if isinstance(repo_probe[1], dict) else {}
        branch = quote(str(meta.get("default_branch", "main")), safe="")
        return repo_probe, self._try(f"{base}/branches/{branch}/protection")

    # SSH keys -----------------------------------------------------------------------
    def collect_user_keys(self, store: Store, now: datetime) -> list[dict[str, Any]]:
        me = self._client.get(f"{API}/user", self._headers).json()
        keys = self._get_all(f"{API}/user/keys?per_page=100")
        current = {str(k["id"]): k.get("created_at", "") for k in keys}
        snapshot = store.get_doc("snapshots", "github:user_keys")
        self.defer("snapshots", "github:user_keys", {"ids": current, "time": format_time(now)})
        if snapshot is None:
            return []  # first run establishes the baseline; no alerts
        added = sorted(set(current) - set(snapshot["ids"]))
        return [
            make_event(
                event_type="ssh_key_added",
                source="github_api",
                asset_id="gh-account",
                time=now,
                severity="medium",
                confidence="high",
                evidence_ref=f"github/user_keys/{key_id}",
                event_id=f"github:user_key:{key_id}",
                identity_ref=self._ident(me.get("login")),
                attributes={"key_id": key_id, "created_at": current[key_id]},
            )
            for key_id in added
        ]

    # workflows and releases ---------------------------------------------------------------
    def collect_repo(
        self, store: Store, repo: str, now: datetime, lookback: timedelta
    ) -> list[dict[str, Any]]:
        cursor_key = f"github:{repo}"
        cursor = store.get_doc("cursors", cursor_key)
        since = cursor["since"] if cursor else format_time(now - lookback)
        asset = asset_id_for_repo(repo)
        base = f"{API}/repos/{quote(repo, safe='/')}"
        events: list[dict[str, Any]] = []

        window_start = format_time(
            datetime.fromisoformat(since.replace("Z", "+00:00")) - timedelta(days=90)
        )
        history = self._get_all(f"{base}/commits?since={window_start}&per_page=100")
        authors = [
            ((c.get("author") or {}).get("login"), c["commit"]["author"]["date"], c["sha"])
            for c in history
        ]
        for c in self._get_all(f"{base}/commits?path=.github/workflows&since={since}&per_page=100"):
            detail = self._client.get(f"{base}/commits/{c['sha']}", self._headers).json()
            files = [
                f for f in detail.get("files", []) if f["filename"].startswith(".github/workflows/")
            ]
            flags = {"adds_network": False, "adds_secret_ref": False, "patch_missing": False}
            for f in files:
                if "patch" not in f:
                    # GitHub omits the diff for large/binary-like changes: content is UNKNOWN,
                    # not safe. Treat it as risky rather than silently "no risky lines".
                    flags["patch_missing"] = True
                    continue
                for name, value in added_line_flags(f["patch"]).items():
                    flags[name] = flags[name] or value
            login = (c.get("author") or {}).get("login")
            when = c["commit"]["author"]["date"]
            earlier = [(a, d) for a, d, sha in authors if sha != c["sha"] and d < when]
            maintainers = {a for a, _d in earlier if a}
            owner = repo.split("/")[0].lower()
            if login and login.lower() == owner:
                is_maintainer, basis = True, "repo owner"
            elif not earlier:
                # The first commits of a repo have no history to compare with: not judged.
                is_maintainer, basis = True, "no earlier commits to compare (not judged)"
            else:
                is_maintainer = bool(login) and login in maintainers
                basis = "commit author login (unverified)"  # author email can be forged
            events.append(
                make_event(
                    event_type="workflow_changed",
                    source="github_api",
                    asset_id=asset,
                    time=datetime.fromisoformat(when.replace("Z", "+00:00")),
                    severity="medium" if any(flags.values()) else "low",  # unknown diff counts
                    confidence="high",
                    evidence_ref=f"github/{repo}/commit/{c['sha']}",
                    event_id=f"github:{repo}:workflow:{c['sha']}",
                    identity_ref=self._ident(login),
                    attributes={
                        **flags,
                        "files": [f["filename"] for f in files],
                        "actor_is_maintainer": is_maintainer,
                        # HYPOTHESIS basis: the author login comes from the commit's author
                        # email, which can be forged; it is not proof of who pushed.
                        "actor_basis": basis,
                        "commit": c["sha"],
                    },
                )
            )
        for rel in self._get_all(f"{base}/releases?per_page=100", limit=200):
            published = rel.get("published_at")
            if not published or published < since:
                continue
            events.append(
                make_event(
                    event_type="release_published",
                    source="github_api",
                    asset_id=asset,
                    time=datetime.fromisoformat(published.replace("Z", "+00:00")),
                    severity="info",
                    confidence="high",
                    evidence_ref=f"github/{repo}/release/{rel['id']}",
                    event_id=f"github:{repo}:release:{rel['id']}",
                    identity_ref=self._ident((rel.get("author") or {}).get("login")),
                    attributes={"tag": rel.get("tag_name", "")},
                )
            )
        self.defer("cursors", cursor_key, {"since": format_time(now)})
        return events
