"""Evidence store — persists replayable runs and findings as JSON.

The evidence model is part of the moat: every run is a replayable trace,
and findings reference the exact run that produced them.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, Run


@dataclass
class EvidenceStore:
    root: str = ".cyberange"
    runs: dict[str, Run] = field(default_factory=dict)
    findings: dict[str, Finding] = field(default_factory=dict)

    def __post_init__(self) -> None:
        os.makedirs(os.path.join(self.root, "runs"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "findings"), exist_ok=True)

    # ------------------------------------------------------------------ #
    def save_run(self, run: Run) -> str:
        self.runs[run.id] = run
        path = os.path.join(self.root, "runs", f"{run.id}.json")
        with open(path, "w") as fh:
            json.dump(run.to_dict(), fh, indent=2, default=str)
        return path

    def save_finding(self, finding: Finding) -> str:
        self.findings[finding.id] = finding
        path = os.path.join(self.root, "findings", f"{finding.id}.json")
        with open(path, "w") as fh:
            json.dump(finding.to_dict(), fh, indent=2, default=str)
        return path

    # ------------------------------------------------------------------ #
    def replay(self, run_id: str) -> dict[str, Any]:
        """Return a step-by-step replay of a stored run (Trace Replay)."""
        run = self.runs.get(run_id)
        if not run:
            path = os.path.join(self.root, "runs", f"{run_id}.json")
            with open(path) as fh:
                return {"replay": json.load(fh)["reasoning_trace"]}
        steps = list(run.reasoning_trace)
        return {
            "run_id": run.id,
            "scenario_id": run.scenario_id,
            "status": run.status.value,
            "steps": steps,
            "tool_calls": [
                f"{tc.tool}:{tc.args.get('arg','')}"
                + (" [BLOCKED]" if tc.blocked else "")
                for tc in run.tool_calls
            ],
            "alerts": [a.title for a in run.alerts],
        }
