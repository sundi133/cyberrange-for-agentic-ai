"""Cyberange HTTP API (optional surface).

A thin FastAPI layer over the shared engine that powers the three team
consoles and the web dashboard. Falls back gracefully if FastAPI is not
installed -- the core, CLI and tests have zero third-party dependencies.

Run with::

    pip install -r requirements.txt
    uvicorn cyberange.api:app --reload
"""

from __future__ import annotations

import os

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
except ImportError as exc:  # pragma: no cover - exercised only without fastapi
    raise SystemExit(
        "FastAPI is required for the API surface: pip install -r requirements.txt"
    ) from exc

from .core.engine import ScenarioEngine
from .core.findings import generate_finding, to_github_issue, to_jira_issue
from .core import report as R
from .core import integrations
from .core.validation import build_matrix
from .scenarios import SCENARIOS, by_id


app = FastAPI(title="Cyberange", version="0.1.0",
              description="A cyber range for agentic AI security.")
engine = ScenarioEngine()

_WEB = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "index.html")


# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    if os.path.exists(_WEB):
        with open(_WEB) as fh:
            return fh.read()
    return "<h1>Cyberange</h1><p>Dashboard asset missing.</p>"


@app.get("/api/scenarios")
def list_scenarios():
    return [s.to_dict() for s in SCENARIOS]


@app.get("/api/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    try:
        return by_id(scenario_id).to_dict()
    except KeyError:
        raise HTTPException(404, "scenario not found")


@app.post("/api/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: str, controls: list[str] | None = None):
    try:
        sc = by_id(scenario_id)
    except KeyError:
        raise HTTPException(404, "scenario not found")
    run = engine.run(sc, controls=controls or [])
    return {"run": run.to_dict(), "red": R.red_dashboard(sc, run)}


@app.post("/api/scenarios/{scenario_id}/retest")
def retest(scenario_id: str):
    """The Purple Team before/after loop."""
    try:
        sc = by_id(scenario_id)
    except KeyError:
        raise HTTPException(404, "scenario not found")
    comparison = engine.re_test(sc)
    finding = generate_finding(sc, comparison.before)
    return {
        "comparison": comparison.summary(),
        "before_trace": comparison.before.reasoning_trace,
        "after_trace": comparison.after.reasoning_trace,
        "finding": finding.to_dict() if finding else None,
    }


@app.get("/api/matrix")
def matrix():
    m = build_matrix(SCENARIOS)
    return {
        cid: {
            "passed": cv.passed,
            "failed": cv.failed,
            "results": [r.__dict__ for r in cv.results],
        }
        for cid, cv in m.items()
    }


@app.get("/api/blue")
def blue():
    runs = [engine.run(s, controls=[]) for s in SCENARIOS]
    return R.blue_dashboard(runs)


@app.get("/api/purple")
def purple():
    comparisons = [engine.re_test(s) for s in SCENARIOS]
    return R.purple_dashboard(comparisons)


@app.get("/api/report")
def report():
    comparisons = [engine.re_test(s) for s in SCENARIOS]
    return {"markdown": R.executive_summary(comparisons)}


@app.get("/api/scenarios/{scenario_id}/export/{kind}")
def export(scenario_id: str, kind: str):
    try:
        sc = by_id(scenario_id)
    except KeyError:
        raise HTTPException(404, "scenario not found")
    run = engine.run(sc, controls=[])
    finding = generate_finding(sc, run)
    if not finding:
        raise HTTPException(409, "attack did not succeed; no finding")
    if kind == "github":
        return to_github_issue(finding)
    if kind == "jira":
        return to_jira_issue(finding)
    if kind == "siem":
        return R.siem_event(run)
    raise HTTPException(400, "kind must be one of github|jira|siem")


@app.get("/api/ctf/challenges")
def ctf_challenges(track: str | None = None):
    from .training.ctf import build_challenges
    return [c.public() for c in build_challenges() if not track or c.track == track]


@app.post("/api/ctf/submit")
def ctf_submit(payload: dict):
    """Body: {participant, challenge, answer}."""
    from .training.ctf import Scoreboard
    try:
        res = Scoreboard().submit(
            payload["participant"], payload["challenge"], payload["answer"])
    except KeyError:
        raise HTTPException(400, "body needs participant, challenge, answer")
    return res.__dict__


@app.get("/api/ctf/score/{participant}")
def ctf_score(participant: str):
    from .training.ctf import Scoreboard
    return Scoreboard().score(participant)


@app.get("/api/ctf/leaderboard")
def ctf_leaderboard():
    from .training.ctf import Scoreboard
    return Scoreboard().leaderboard()


@app.get("/api/integrations")
def integration_status():
    """Which live export integrations are configured via env vars."""
    return {t: integrations.configured(t) for t in ("siem", "github", "jira")}


@app.post("/api/scenarios/{scenario_id}/push/{target}")
def push(scenario_id: str, target: str):
    """Deliver a scenario's finding/alerts to a real external system."""
    try:
        sc = by_id(scenario_id)
    except KeyError:
        raise HTTPException(404, "scenario not found")
    if not integrations.configured(target):
        raise HTTPException(409, f"integration '{target}' is not configured")
    run = engine.run(sc, controls=[])
    try:
        if target == "siem":
            result = integrations.send_siem(R.siem_event(run))
        else:
            finding = generate_finding(sc, run)
            if not finding:
                raise HTTPException(409, "attack did not succeed; no finding")
            if target == "github":
                result = integrations.create_github_issue(to_github_issue(finding))
            elif target == "jira":
                result = integrations.create_jira_issue(to_jira_issue(finding))
            else:
                raise HTTPException(400, "target must be siem|github|jira")
    except integrations.IntegrationError as e:
        raise HTTPException(400, str(e))
    return result.__dict__
