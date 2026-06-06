"""Scenario engine — the orchestrator behind every team surface.

A single ``run`` drives the shared loop:

    build sandbox -> apply controls -> run agent -> record trace ->
    run detections -> evaluate success

``re_test`` runs the same scenario with a set of controls enabled and
returns a before/after comparison, which is the heart of the Purple Team
workflow.
"""

from __future__ import annotations

from dataclasses import dataclass

from .agent import SimAgent
from .detections import run_detections
from .policy import PolicyEngine
from .tools import ToolSandbox
from ..models import Run, RunStatus, Scenario


@dataclass
class Comparison:
    """Before/after result of a re-test (Purple Team)."""

    scenario_id: str
    before: Run
    after: Run

    @property
    def fixed(self) -> bool:
        return self.before.attack_succeeded and not self.after.attack_succeeded

    @property
    def detection_fired(self) -> bool:
        # "Did the detection fire?" -> did Blue catch the original attack.
        # (A root-cause fix means the hardened agent never even attempts, so
        # we prove detection against the attack that actually happened.)
        return self.before.detected

    @property
    def safe_task_preserved(self) -> bool:
        # The benign task should still complete after hardening.
        return self.after.final_output.startswith("[task complete]")

    @property
    def control_status(self) -> str:
        if self.fixed and self.detection_fired and self.safe_task_preserved:
            return "validated"
        if self.fixed:
            return "fixed_no_detection"
        return "failed"

    def summary(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "before": self.before.status.value,
            "after": self.after.status.value,
            "fixed": self.fixed,
            "detection_fired": self.detection_fired,
            "safe_task_preserved": self.safe_task_preserved,
            "control_status": self.control_status,
            "controls_applied": self.after.controls,
        }


class ScenarioEngine:
    def __init__(self, agent: SimAgent | None = None):
        self.agent = agent or SimAgent()

    # ------------------------------------------------------------------ #
    def run(
        self,
        scenario: Scenario,
        controls: list[str] | None = None,
        detection_rules: list[str] | None = None,
    ) -> Run:
        """Execute one scenario run end-to-end."""
        sandbox = ToolSandbox.from_seed(scenario.seed_data)
        policy = PolicyEngine(active=controls or [])
        run = self.agent.run(scenario, sandbox, policy)

        # Blue Team: detections always evaluate the recorded trace.
        rules = detection_rules if detection_rules is not None else scenario.detection_rules
        run.alerts = run_detections(run, rules or None)
        return run

    # ------------------------------------------------------------------ #
    def re_test(
        self,
        scenario: Scenario,
        controls: list[str] | None = None,
        detection_rules: list[str] | None = None,
    ) -> Comparison:
        """Run the scenario with no controls, then with controls (Purple)."""
        controls = controls if controls is not None else scenario.mapped_controls
        before = self.run(scenario, controls=[], detection_rules=detection_rules)
        after = self.run(scenario, controls=controls, detection_rules=detection_rules)
        return Comparison(scenario_id=scenario.id, before=before, after=after)
