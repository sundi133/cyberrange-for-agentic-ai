"""Live export integrations — SIEM webhook, GitHub issues, Jira issues.

These take the *payloads* produced by ``findings.py`` / ``report.py`` and
actually deliver them to real endpoints over HTTPS. Configuration is via
environment variables so no secrets live in code. Implemented with the
standard library (``urllib``) so the core stays dependency-free.

Env vars:
    SIEM     -> CYBERANGE_SIEM_WEBHOOK_URL  [, CYBERANGE_SIEM_AUTH_HEADER]
    GitHub   -> GITHUB_TOKEN, GITHUB_REPOSITORY (owner/repo)
    Jira     -> JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass


class IntegrationError(RuntimeError):
    pass


@dataclass
class DeliveryResult:
    target: str
    ok: bool
    status: int | None = None
    detail: str = ""
    url: str | None = None

    def __str__(self) -> str:
        state = "OK" if self.ok else "FAIL"
        return f"[{state}] {self.target} ({self.status}) {self.detail}".rstrip()


def _post(url: str, payload: dict, headers: dict[str, str]) -> tuple[int, str]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


# --------------------------------------------------------------------------- #
# SIEM webhook
# --------------------------------------------------------------------------- #
def configured(target: str) -> bool:
    if target == "siem":
        return bool(os.environ.get("CYBERANGE_SIEM_WEBHOOK_URL"))
    if target == "github":
        return bool(os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_REPOSITORY"))
    if target == "jira":
        return all(
            os.environ.get(v)
            for v in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY")
        )
    return False


def send_siem(events: list[dict]) -> DeliveryResult:
    url = os.environ.get("CYBERANGE_SIEM_WEBHOOK_URL")
    if not url:
        raise IntegrationError("CYBERANGE_SIEM_WEBHOOK_URL not set")
    headers = {}
    if os.environ.get("CYBERANGE_SIEM_AUTH_HEADER"):
        # e.g. "Authorization: Bearer xyz"
        name, _, value = os.environ["CYBERANGE_SIEM_AUTH_HEADER"].partition(":")
        headers[name.strip()] = value.strip()
    status, body = _post(url, {"events": events}, headers)
    return DeliveryResult("siem", 200 <= status < 300, status, body[:200], url)


# --------------------------------------------------------------------------- #
# GitHub issue
# --------------------------------------------------------------------------- #
def create_github_issue(issue: dict) -> DeliveryResult:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (token and repo):
        raise IntegrationError("GITHUB_TOKEN and GITHUB_REPOSITORY required")
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    status, body = _post(url, issue, headers)
    detail = ""
    try:
        detail = json.loads(body).get("html_url", "")
    except Exception:
        detail = body[:200]
    return DeliveryResult("github", 200 <= status < 300, status, detail, url)


# --------------------------------------------------------------------------- #
# Jira issue
# --------------------------------------------------------------------------- #
def create_jira_issue(issue: dict) -> DeliveryResult:
    base = os.environ.get("JIRA_BASE_URL")
    email = os.environ.get("JIRA_EMAIL")
    token = os.environ.get("JIRA_API_TOKEN")
    project = os.environ.get("JIRA_PROJECT_KEY")
    if not all((base, email, token, project)):
        raise IntegrationError("JIRA_BASE_URL/EMAIL/API_TOKEN/PROJECT_KEY required")
    # Ensure the project key is present.
    issue = json.loads(json.dumps(issue))  # shallow copy
    issue.setdefault("fields", {})["project"] = {"key": project}
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    url = base.rstrip("/") + "/rest/api/3/issue"
    status, body = _post(url, issue, {"Authorization": f"Basic {auth}"})
    detail = ""
    try:
        detail = json.loads(body).get("key", body[:200])
    except Exception:
        detail = body[:200]
    return DeliveryResult("jira", 200 <= status < 300, status, str(detail), url)
