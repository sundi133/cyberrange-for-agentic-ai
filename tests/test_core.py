"""Unit tests for the shared core (policy, agent, evidence, detections)."""

import os
import tempfile

from cyberange.core.agent import SimAgent
from cyberange.core.detections import run_detections
from cyberange.core.engine import ScenarioEngine
from cyberange.core.evidence import EvidenceStore
from cyberange.core.policy import Action, PolicyEngine, CONTROLS
from cyberange.core.tools import ToolSandbox
from cyberange.models import RunStatus, Severity
from cyberange.scenarios import by_id


def test_policy_blocks_external_email():
    pe = PolicyEngine(["external_email_approval"])
    allowed, ev = pe.evaluate(Action("send_email", "x@evil.com", {"external": True}))
    assert not allowed and ev.decision == "block"


def test_policy_allows_internal_email():
    pe = PolicyEngine(["external_email_approval"])
    allowed, ev = pe.evaluate(Action("send_email", "a@acme.internal", {"external": False}))
    assert allowed and ev is None


def test_channel_aware_neutralization():
    pe = PolicyEngine(["trusted_retrieval_only"])
    assert pe.neutralizes_for("rag")
    assert not pe.neutralizes_for("email")
    pe2 = PolicyEngine(["untrusted_content_separation"])
    assert pe2.neutralizes_for("email") and pe2.neutralizes_for("memory")


def test_all_controls_have_unique_ids():
    assert len(CONTROLS) == len({c.id for c in CONTROLS.values()})


def test_tool_sandbox_from_seed():
    sb = ToolSandbox.from_seed({"documents": [
        {"doc_id": "d1", "title": "t", "classification": "restricted", "content": "x"}
    ]})
    res = sb.read_doc("d1")
    assert res.ok and res.classification == "restricted"


def test_agent_runs_safe_task_with_no_payload():
    sc = by_id("SC-001")
    # Run with the root control; agent should ignore injection but finish task.
    run = ScenarioEngine().run(sc, controls=["untrusted_content_separation"])
    assert run.status == RunStatus.ATTACK_BLOCKED
    assert run.final_output.startswith("[task complete]")


def test_evidence_store_roundtrip_and_replay():
    with tempfile.TemporaryDirectory() as d:
        store = EvidenceStore(root=d)
        run = ScenarioEngine().run(by_id("SC-001"), controls=[])
        path = store.save_run(run)
        assert os.path.exists(path)
        replay = store.replay(run.id)
        assert replay["run_id"] == run.id
        assert replay["steps"]
        assert any("BLOCKED" not in s for s in replay["tool_calls"])


def test_detection_decoupled_from_policy():
    """Detection fires on a vulnerable run even though nothing was blocked."""
    run = ScenarioEngine().run(by_id("SC-007"), controls=[])
    assert run.blocked_actions == []
    alerts = run_detections(run)
    assert any(a.severity == Severity.CRITICAL for a in alerts)
