"""Reporting engine + SIEM export.

Produces the three team-specific surfaces over a shared set of runs:

    red_dashboard    -- attack objective, payload, trace, severity, finding
    blue_dashboard   -- alerts, blocked actions, MTTD/MTTC, coverage
    purple_dashboard -- before/after, control validation matrix
"""

from __future__ import annotations

from .detections import DETECTIONS
from .engine import Comparison
from .findings import generate_finding
from ..models import Run, Scenario


# --------------------------------------------------------------------------- #
# Red Team
# --------------------------------------------------------------------------- #
def red_dashboard(scenario: Scenario, run: Run) -> dict:
    finding = generate_finding(scenario, run)
    return {
        "attack_objective": scenario.attacker_goal,
        "payload": scenario.attack_payload.hidden_instruction
        if scenario.attack_payload
        else "",
        "agent_reasoning_trace": run.reasoning_trace,
        "retrieved_documents": [
            {"doc_id": d.doc_id, "classification": d.classification}
            for d in run.retrieved_context
        ],
        "tool_calls": [
            {"tool": tc.tool, "arg": tc.args.get("arg", ""), "blocked": tc.blocked}
            for tc in run.tool_calls
        ],
        "policy_violations": [pe.reason for pe in run.policy_events],
        "exfiltration_attempt": "data_exfiltration" in run.met_success_conditions,
        "severity": scenario.severity.value,
        "suggested_finding": finding.to_markdown() if finding else None,
    }


# --------------------------------------------------------------------------- #
# Blue Team
# --------------------------------------------------------------------------- #
def blue_dashboard(runs: list[Run]) -> dict:
    total_attacks = sum(1 for r in runs if r.attack_succeeded)
    detected_attacks = sum(1 for r in runs if r.attack_succeeded and r.detected)
    coverage = (
        round(100 * detected_attacks / total_attacks) if total_attacks else 100
    )
    return {
        "live_risk_events": [
            {
                "run_id": r.id,
                "scenario_id": r.scenario_id,
                "alerts": [a.title for a in r.alerts],
                "severity": _max_alert_sev(r),
            }
            for r in runs
            if r.alerts
        ],
        "blocked_actions": sum(len(r.blocked_actions) for r in runs),
        "sensitive_data_touches": sum(
            1
            for r in runs
            for d in r.retrieved_context
            if d.classification == "restricted"
        ),
        "memory_writes": sum(len(r.memory_events) for r in runs),
        "policy_violations": sum(len(r.policy_events) for r in runs),
        "detection_coverage_pct": coverage,
        # Simulated timings -- detection is synchronous in the range.
        "mean_time_to_detect_s": 0.2 if detected_attacks else None,
        "mean_time_to_contain_s": 1.0 if any(r.blocked_actions for r in runs) else None,
        "rules": [{"id": d.id, "severity": d.severity.value} for d in DETECTIONS],
    }


def _max_alert_sev(run: Run) -> str:
    if not run.alerts:
        return "info"
    return max(run.alerts, key=lambda a: a.severity.rank).severity.value


def siem_event(run: Run) -> list[dict]:
    """Flatten a run's alerts into SIEM-ready events (webhook payload)."""
    return [
        {
            "vendor": "cyberange",
            "product": "agentic-range",
            "event_type": "detection",
            "rule_id": a.rule_id,
            "title": a.title,
            "severity": a.severity.value,
            "signal": a.signal,
            "recommended_response": a.recommended_response,
            "run_id": run.id,
            "scenario_id": run.scenario_id,
            "timestamp": a.ts,
        }
        for a in run.alerts
    ]


# --------------------------------------------------------------------------- #
# Purple Team
# --------------------------------------------------------------------------- #
def purple_dashboard(comparisons: list[Comparison]) -> dict:
    return {
        "scenarios": [c.summary() for c in comparisons],
        "validated": sum(1 for c in comparisons if c.control_status == "validated"),
        "failed": sum(1 for c in comparisons if c.control_status == "failed"),
        "false_positive_risk": _false_positive_note(comparisons),
    }


def _false_positive_note(comparisons: list[Comparison]) -> str:
    broke_task = [c for c in comparisons if not c.safe_task_preserved]
    if broke_task:
        return (
            f"{len(broke_task)} scenario(s) had the safe task broken by the "
            "control — investigate false positives."
        )
    return "No safe-task regressions detected."


# --------------------------------------------------------------------------- #
# Executive / GRC summary
# --------------------------------------------------------------------------- #
def executive_summary(comparisons: list[Comparison]) -> str:
    total = len(comparisons)
    validated = sum(1 for c in comparisons if c.control_status == "validated")
    fixed = sum(1 for c in comparisons if c.fixed)
    lines = [
        "# Cyberange — Agentic AI Security Report",
        "",
        f"Scenarios exercised: **{total}**",
        f"Controls validated (fixed + detected + safe task preserved): "
        f"**{validated}/{total}**",
        f"Attacks remediated: **{fixed}/{total}**",
        "",
        "## Per-scenario results",
        "",
        "| Scenario | Before | After | Control status |",
        "| --- | --- | --- | --- |",
    ]
    for c in comparisons:
        lines.append(
            f"| {c.scenario_id} | {c.before.status.value} | "
            f"{c.after.status.value} | {c.control_status} |"
        )
    return "\n".join(lines)
