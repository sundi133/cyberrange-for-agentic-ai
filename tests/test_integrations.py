"""Tests for the CI gate, live-export integrations, and LiveAgent wiring.

These cover everything that does NOT require network access or an API key:
payload shaping, env-var gating, and module/interface integrity.
"""

import json

import pytest

from cyberange.ci_gate import main as ci_gate_main
from cyberange.core import integrations
from cyberange.core.findings import generate_finding, to_github_issue, to_jira_issue
from cyberange.core.engine import ScenarioEngine
from cyberange.scenarios import by_id


# --------------------------------------------------------------------------- #
# CI gate
# --------------------------------------------------------------------------- #
def test_ci_gate_passes():
    assert ci_gate_main() == 0


# --------------------------------------------------------------------------- #
# Integrations — gating + error handling (no network)
# --------------------------------------------------------------------------- #
def test_integrations_unconfigured_by_default(monkeypatch):
    for var in ("CYBERANGE_SIEM_WEBHOOK_URL", "GITHUB_TOKEN", "GITHUB_REPOSITORY",
                "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert not integrations.configured("siem")
    assert not integrations.configured("github")
    assert not integrations.configured("jira")


def test_integrations_configured_detection(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    assert integrations.configured("github")


def test_integrations_raise_when_unconfigured(monkeypatch):
    monkeypatch.delenv("CYBERANGE_SIEM_WEBHOOK_URL", raising=False)
    with pytest.raises(integrations.IntegrationError):
        integrations.send_siem([{"x": 1}])


def test_delivery_result_str():
    r = integrations.DeliveryResult("github", True, 201, "https://x/issues/1")
    assert "OK" in str(r) and "github" in str(r)


def test_siem_post_payload(monkeypatch):
    """send_siem should POST a wrapped {events:[...]} body to the webhook."""
    captured = {}

    def fake_post(url, payload, headers):
        captured["url"] = url
        captured["payload"] = payload
        captured["headers"] = headers
        return 200, "ok"

    monkeypatch.setenv("CYBERANGE_SIEM_WEBHOOK_URL", "https://siem.example/hook")
    monkeypatch.setenv("CYBERANGE_SIEM_AUTH_HEADER", "Authorization: Bearer tok")
    monkeypatch.setattr(integrations, "_post", fake_post)

    run = ScenarioEngine().run(by_id("SC-001"), controls=[])
    from cyberange.core import report as R
    result = integrations.send_siem(R.siem_event(run))

    assert result.ok
    assert captured["url"] == "https://siem.example/hook"
    assert "events" in captured["payload"]
    assert captured["headers"]["Authorization"] == "Bearer tok"


def test_jira_payload_injects_project(monkeypatch):
    captured = {}

    def fake_post(url, payload, headers):
        captured["payload"] = payload
        return 201, json.dumps({"key": "SEC-1"})

    monkeypatch.setenv("JIRA_BASE_URL", "https://acme.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "a@b.c")
    monkeypatch.setenv("JIRA_API_TOKEN", "tok")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")
    monkeypatch.setattr(integrations, "_post", fake_post)

    run = ScenarioEngine().run(by_id("SC-001"), controls=[])
    finding = generate_finding(by_id("SC-001"), run)
    result = integrations.create_jira_issue(to_jira_issue(finding))

    assert result.ok and result.detail == "SEC-1"
    assert captured["payload"]["fields"]["project"] == {"key": "SEC"}


def test_github_payload_shape(monkeypatch):
    captured = {}

    def fake_post(url, payload, headers):
        captured["url"] = url
        captured["headers"] = headers
        return 201, json.dumps({"html_url": "https://github.com/o/r/issues/1"})

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setattr(integrations, "_post", fake_post)

    run = ScenarioEngine().run(by_id("SC-001"), controls=[])
    finding = generate_finding(by_id("SC-001"), run)
    result = integrations.create_github_issue(to_github_issue(finding))

    assert result.ok
    assert captured["url"] == "https://api.github.com/repos/o/r/issues"
    assert captured["headers"]["Authorization"] == "Bearer ghp_x"


# --------------------------------------------------------------------------- #
# LiveAgent — interface integrity (no network / no SDK required)
# --------------------------------------------------------------------------- #
def test_live_agent_imports_without_sdk():
    from cyberange.core.live_agent import LiveAgent, DEFAULT_MODEL
    agent = LiveAgent()
    assert DEFAULT_MODEL == "claude-opus-4-8"
    assert agent.agent_id and hasattr(agent, "run")


def test_live_agent_lazy_export():
    from cyberange.core import LiveAgent
    assert LiveAgent.__name__ == "LiveAgent"
