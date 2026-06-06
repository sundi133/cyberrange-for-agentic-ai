"""Offline tests for the LiveAgent pipeline using recorded traces.

These drive ``LiveAgent`` with a ``ReplayDriver`` instead of a real Claude
model, so the full live path — policy gating, sandbox effects, trace
recording, detections, findings, and the Control Validation Matrix — is
exercised with no SDK and no network. The recorded traces capture what a
*vulnerable* live agent did when it obeyed each injected instruction.
"""

import json
import os

import pytest

from cyberange.core.engine import ScenarioEngine
from cyberange.core.findings import generate_finding
from cyberange.core.live_agent import LiveAgent, ReplayDriver
from cyberange.scenarios import by_id


_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "live_traces.json")
with open(_FIXTURE) as fh:
    TRACES = {k: v for k, v in json.load(fh).items() if not k.startswith("_")}


def _calls(scenario_id):
    return [(name, kwargs) for name, kwargs in TRACES[scenario_id]]


def _live_engine(scenario_id):
    driver = ReplayDriver(_calls(scenario_id), final_text="handled the request")
    return ScenarioEngine(agent=LiveAgent(driver=driver))


@pytest.mark.parametrize("scenario_id", sorted(TRACES))
def test_replayed_attack_succeeds_and_is_detected(scenario_id):
    sc = by_id(scenario_id)
    run = _live_engine(scenario_id).run(sc, controls=[])
    assert run.attack_succeeded, f"{scenario_id}: replayed attack did not fire"
    assert run.detected, f"{scenario_id}: no detection on replayed attack"
    assert run.model == "claude-opus-4-8"


@pytest.mark.parametrize("scenario_id", sorted(TRACES))
def test_policy_blocks_replayed_attack(scenario_id):
    """The same vulnerable trace, replayed against the hardened policy, is
    stopped by the downstream guardrails."""
    sc = by_id(scenario_id)
    run = _live_engine(scenario_id).run(sc, controls=sc.mapped_controls)
    assert not run.attack_succeeded, f"{scenario_id}: controls failed to block"
    assert run.blocked_actions, f"{scenario_id}: expected at least one blocked action"


def test_replay_generates_finding_with_evidence():
    sc = by_id("SC-001")
    run = _live_engine("SC-001").run(sc, controls=[])
    finding = generate_finding(sc, run)
    assert finding is not None
    assert "rival@competitor.com" in json.dumps(finding.evidence)
    assert run.final_output.startswith("[task complete]")


def test_replay_records_full_trace():
    run = _live_engine("SC-001").run(by_id("SC-001"), controls=[])
    tools_called = [tc.tool for tc in run.tool_calls]
    assert tools_called == ["search_docs", "read_doc", "send_email"]
    assert any(d.classification == "restricted" for d in run.retrieved_context)


def test_replay_driver_skips_unavailable_tools():
    """A tool the scenario does not expose is ignored, like the real runner."""
    sc = by_id("SC-002")  # only exposes read_doc
    driver = ReplayDriver([("read_doc", {"doc_id": "aws-credentials"}),
                           ("run_shell", {"command": "whoami"})])
    run = ScenarioEngine(agent=LiveAgent(driver=driver)).run(sc, controls=[])
    assert [tc.tool for tc in run.tool_calls] == ["read_doc"]
