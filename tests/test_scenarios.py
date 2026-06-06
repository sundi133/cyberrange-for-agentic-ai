"""End-to-end behavior tests for the Cyberange scenario library."""

import pytest

from cyberange.core.engine import ScenarioEngine
from cyberange.core.findings import generate_finding, to_github_issue, to_jira_issue
from cyberange.core.validation import build_matrix, validate_control
from cyberange.core import report as R
from cyberange.scenarios import SCENARIOS, by_id


engine = ScenarioEngine()


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_attack_succeeds_without_controls(scenario):
    """Every seeded attack must succeed against an undefended agent."""
    run = engine.run(scenario, controls=[])
    assert run.attack_succeeded, f"{scenario.id} did not fire"
    assert run.met_success_conditions


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_attack_blocked_with_mapped_controls(scenario):
    """All mapped controls together must neutralize the attack."""
    run = engine.run(scenario, controls=scenario.mapped_controls)
    assert not run.attack_succeeded, f"{scenario.id} not blocked"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_safe_task_preserved_after_hardening(scenario):
    run = engine.run(scenario, controls=scenario.mapped_controls)
    assert run.final_output.startswith("[task complete]")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_detection_fires_on_attack(scenario):
    """Blue Team detections must catch every successful attack."""
    run = engine.run(scenario, controls=[])
    assert run.detected, f"no detection for {scenario.id}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_finding_generated_on_success(scenario):
    run = engine.run(scenario, controls=[])
    finding = generate_finding(scenario, run)
    assert finding is not None
    assert finding.severity == scenario.severity
    assert finding.scenario_id == scenario.id
    assert "Finding:" in finding.to_markdown()


def test_no_finding_when_blocked():
    sc = by_id("SC-001")
    run = engine.run(sc, controls=sc.mapped_controls)
    assert generate_finding(sc, run) is None


def test_re_test_validates_control():
    sc = by_id("SC-001")
    comparison = engine.re_test(sc)
    assert comparison.before.attack_succeeded
    assert not comparison.after.attack_succeeded
    assert comparison.fixed
    assert comparison.detection_fired
    assert comparison.safe_task_preserved
    assert comparison.control_status == "validated"


def test_each_mapped_control_individually_blocks():
    """Every individually-mapped control should defend its scenario."""
    for sc in SCENARIOS:
        for cid in sc.mapped_controls:
            cv = validate_control(cid, [sc])
            cell = cv.results[0]
            assert cell.status == "passed", (
                f"control {cid} failed to defend {sc.id}: {cell.detail}"
            )


def test_matrix_separation_covers_all():
    matrix = build_matrix(SCENARIOS)
    sep = matrix["untrusted_content_separation"]
    assert sep.passed == len(SCENARIOS)
    assert sep.failed == 0


def test_blue_dashboard_full_coverage():
    runs = [engine.run(s, controls=[]) for s in SCENARIOS]
    dash = R.blue_dashboard(runs)
    assert dash["detection_coverage_pct"] == 100


def test_siem_export_shape():
    run = engine.run(by_id("SC-001"), controls=[])
    events = R.siem_event(run)
    assert events and all(e["vendor"] == "cyberange" for e in events)
    assert all("rule_id" in e and "severity" in e for e in events)


def test_ticket_exports():
    run = engine.run(by_id("SC-001"), controls=[])
    finding = generate_finding(by_id("SC-001"), run)
    gh = to_github_issue(finding)
    jira = to_jira_issue(finding)
    assert gh["title"].startswith("[Cyberange]")
    assert "cyberange" in gh["labels"]
    assert jira["fields"]["priority"]["name"] == "High"
