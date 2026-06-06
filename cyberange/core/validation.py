"""Control Validation Matrix — the Purple Team killer feature.

For a given control, run every relevant scenario with that control enabled
and record whether the attack is blocked. The result answers the question
enterprises actually ask: *"Can we prove the control works?"*
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .engine import ScenarioEngine
from ..models import Scenario


@dataclass
class CellResult:
    scenario_id: str
    scenario_name: str
    status: str  # passed | failed | not_tested
    detail: str = ""


@dataclass
class ControlValidation:
    control_id: str
    results: list[CellResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == "passed")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "failed")

    def to_text(self) -> str:
        lines = [f"Control: {self.control_id}", "Tested against:"]
        for r in self.results:
            lines.append(f"- {r.scenario_name}: {r.status}")
        return "\n".join(lines)


def validate_control(
    control_id: str,
    scenarios: list[Scenario],
    engine: ScenarioEngine | None = None,
) -> ControlValidation:
    """Run each scenario with ``control_id`` enabled; record pass/fail."""
    engine = engine or ScenarioEngine()
    cv = ControlValidation(control_id=control_id)
    for sc in scenarios:
        # Only meaningful where the scenario maps to this control.
        if control_id not in sc.mapped_controls:
            cv.results.append(
                CellResult(sc.id, sc.name, "not_tested", "control not mapped")
            )
            continue
        run = engine.run(sc, controls=[control_id])
        status = "passed" if not run.attack_succeeded else "failed"
        detail = (
            "attack blocked"
            if status == "passed"
            else f"attacker conditions met: {run.met_success_conditions}"
        )
        cv.results.append(CellResult(sc.id, sc.name, status, detail))
    return cv


def build_matrix(
    scenarios: list[Scenario],
    control_ids: list[str] | None = None,
    engine: ScenarioEngine | None = None,
) -> dict[str, ControlValidation]:
    """Full matrix: every control x every scenario it maps to."""
    engine = engine or ScenarioEngine()
    if control_ids is None:
        control_ids = sorted(
            {c for sc in scenarios for c in sc.mapped_controls}
        )
    return {
        cid: validate_control(cid, scenarios, engine) for cid in control_ids
    }
