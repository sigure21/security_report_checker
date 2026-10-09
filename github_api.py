from __future__ import annotations

import re
import time
from urllib.parse import urlparse
import requests

API = "https://api.github.com"
API_VERSION = "2026-03-10"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"


class GitHubAPIError(RuntimeError):
    pass


def repository_from_input(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        return value[:-4] if value.endswith(".git") else value
    try:
        u = urlparse(value)
        if u.netloc.lower() not in {"github.com", "www.github.com"}:
            return None
        parts = [p for p in u.path.split("/") if p]
        if len(parts) >= 2:
            repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
            return f"{parts[0]}/{repo}"
    except Exception:
        return None
    return None


def request_device_code(client_id: str, scope: str = "repo", timeout: int = 20) -> dict:
    """Start GitHub OAuth Device Flow. No client secret is required."""
    r = requests.post(
        GITHUB_DEVICE_CODE_URL,
        data={"client_id": client_id, "scope": scope},
        headers={"Accept": "application/json", "User-Agent": "GitHubVulnTracker/0.4"},
        timeout=timeout,
    )
    if not r.ok:
        raise GitHubAPIError(f"GitHub OAuth {r.status_code}: {r.text[:300]}")
    data = r.json()
    if not data.get("device_code") or not data.get("user_code"):
        raise GitHubAPIError(data.get("error_description") or data.get("error") or "Device code를 받지 못했습니다.")
    return data


def poll_device_token(client_id: str, device_code: str, interval: int = 5,
                      expires_in: int = 900, timeout: int = 20,
                      should_stop=None) -> dict:
    """Poll GitHub until the device authorization completes or expires."""
    deadline = time.monotonic() + expires_in
    wait = max(5, int(interval or 5))
    while time.monotonic() < deadline:
        if should_stop and should_stop():
            raise GitHubAPIError("GitHub 로그인이 취소되었습니다.")
        time.sleep(wait)
        r = requests.post(
            GITHUB_ACCESS_TOKEN_URL,
            data={
                "client_id": client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={"Accept": "application/json", "User-Agent": "GitHubVulnTracker/0.4"},
            timeout=timeout,
        )
        if not r.ok:
            raise GitHubAPIError(f"GitHub OAuth {r.status_code}: {r.text[:300]}")
        data = r.json()
        if data.get("access_token"):
            return data
        error = data.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            wait += 5
            continue
        if error == "expired_token":
            raise GitHubAPIError("인증 코드가 만료되었습니다. 다시 로그인해 주세요.")
        if error == "access_denied":
            raise GitHubAPIError("GitHub에서 인증이 거부되었습니다.")
        raise GitHubAPIError(data.get("error_description") or error or "GitHub OAuth 인증 실패")
    raise GitHubAPIError("GitHub 인증 시간이 만료되었습니다. 다시 로그인해 주세요.")


class GitHubClient:
    def __init__(self, token: str, timeout: int = 20):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "GitHubVulnTracker/0.4",
        })

    def _get(self, path: str, params=None):
        r = self.session.get(API + path, params=params, timeout=self.timeout)
        if not r.ok:
            try:
                msg = r.json().get("message", "")
            except Exception:
                msg = r.text[:300]
            raise GitHubAPIError(f"GitHub API {r.status_code}: {msg or r.reason}")
        return r

    def current_user(self) -> str:
        return self._get("/user").json()["login"]

    def current_user_details(self) -> dict:
        data = self._get("/user").json()
        return {"login": data.get("login"), "name": data.get("name"), "avatar_url": data.get("avatar_url")}

    def list_repository_advisories(self, repository: str):
        owner, repo = repository.split("/", 1)
        page, all_items = 1, []
        while True:
            r = self._get(f"/repos/{owner}/{repo}/security-advisories", params={"per_page": 100, "page": page, "sort": "updated", "direction": "desc"})
            items = r.json()
            if not isinstance(items, list):
                raise GitHubAPIError(f"예상하지 못한 응답: {repository}")
            all_items.extend(items)
            if len(items) < 100:
                break
            page += 1
        return all_items

    @staticmethod
    def is_users_advisory(advisory: dict, login: str) -> bool:
        login = login.lower()
        candidates = set()
        author = advisory.get("author") or {}
        if author.get("login"):
            candidates.add(author["login"].lower())
        for x in advisory.get("collaborating_users") or []:
            if isinstance(x, dict) and x.get("login"):
                candidates.add(x["login"].lower())
        for x in advisory.get("credits") or []:
            if isinstance(x, dict):
                user = x.get("user") or x
                if isinstance(user, dict) and user.get("login"):
                    candidates.add(user["login"].lower())
        for x in advisory.get("credits_detailed") or []:
            if isinstance(x, dict):
                user = x.get("user") or {}
                if user.get("login"):
                    candidates.add(user["login"].lower())
        return login in candidates

    def sync_repository(self, repository: str, login: str):
        mine = []
        for a in self.list_repository_advisories(repository):
            if self.is_users_advisory(a, login):
                mine.append({
                    "repository": repository,
                    "title": a.get("summary") or "(제목 없음)",
                    "ghsa_id": a.get("ghsa_id"),
                    "cve_id": a.get("cve_id"),
                    "state": a.get("state") or "unknown",
                    "severity": a.get("severity"),
                    "html_url": a.get("html_url"),
                    "submitted_at": a.get("created_at"),
                    "updated_at": a.get("updated_at"),
                    "source": "github",
                })
        return mine
