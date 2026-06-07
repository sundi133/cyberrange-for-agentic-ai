"""Cyberange CTF / scoring engine.

Turns the scenario library into a capture-the-flag training game with three
per-scenario challenges — one per team track — auto-graded by the same engine
that powers the platform:

  * red-<SC>    : exploit the agent — name the attacker objective you achieved.
  * blue-<SC>   : detect — name a detection rule that fires on the attack.
  * purple-<SC> : defend — name control(s) that block the attack.

Solving a challenge awards points and a flag, persisted per participant under
``.cyberange/ctf/<participant>.json``. A leaderboard aggregates participants.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from ..core.detections import DETECTIONS_BY_ID, run_detections
from ..core.engine import ScenarioEngine
from ..core.policy import CONTROLS
from ..models import Scenario, Severity
from ..scenarios import SCENARIOS, by_id


TRACKS = ("red", "blue", "purple")
_POINTS = {Severity.INFO: 10, Severity.LOW: 15, Severity.MEDIUM: 25,
           Severity.HIGH: 40, Severity.CRITICAL: 60}
_TRACK_BONUS = {"red": 0, "blue": 0, "purple": 10}  # defending is hardest


@dataclass
class Challenge:
    id: str
    track: str
    scenario_id: str
    title: str
    prompt: str
    points: int
    difficulty: str

    def public(self) -> dict:
        return {"id": self.id, "track": self.track, "scenario_id": self.scenario_id,
                "title": self.title, "prompt": self.prompt, "points": self.points,
                "difficulty": self.difficulty}


@dataclass
class SubmitResult:
    correct: bool
    points: int
    message: str
    flag: str | None = None
    already_solved: bool = False


def _points_for(sc: Scenario, track: str) -> int:
    return _POINTS[sc.severity] + _TRACK_BONUS[track]


def _difficulty(sc: Scenario) -> str:
    return {Severity.CRITICAL: "hard", Severity.HIGH: "medium"}.get(
        sc.severity, "easy")


def build_challenges() -> list[Challenge]:
    prompts = {
        "red": "Exploit the undefended agent. What attacker objective did it "
               "achieve? (e.g. data_exfiltration, shell_executed)",
        "blue": "The attack fired. Name a detection rule id that catches it "
                "(e.g. DR-003-sensitive-egress).",
        "purple": "Defend the agent. Name the control id(s) that block this "
                  "attack (comma-separated).",
    }
    challenges = []
    for sc in SCENARIOS:
        for track in TRACKS:
            challenges.append(Challenge(
                id=f"{track}-{sc.id}",
                track=track,
                scenario_id=sc.id,
                title=f"{sc.id}: {sc.name}",
                prompt=prompts[track],
                points=_points_for(sc, track),
                difficulty=_difficulty(sc),
            ))
    return challenges


CHALLENGES = {c.id: c for c in build_challenges()}


# --------------------------------------------------------------------------- #
# Grading
# --------------------------------------------------------------------------- #
def _norm(s: str) -> str:
    return s.strip().lower().replace(" ", "")


def grade(challenge: Challenge, answer: str) -> tuple[bool, str]:
    """Grade an answer by actually running the engine. Returns (ok, message)."""
    engine = ScenarioEngine()
    sc = by_id(challenge.scenario_id)
    vuln = engine.run(sc, controls=[])

    if challenge.track == "red":
        achieved = {_norm(c) for c in vuln.met_success_conditions}
        if _norm(answer) in achieved:
            return True, f"Correct — agent achieved {answer.strip()}."
        return False, ("Not an objective the agent achieved here. Hint: run "
                       f"`cyberange run {sc.id}` and read 'attacker achieved'.")

    if challenge.track == "blue":
        fired = {d.rule_id.lower() for d in run_detections(vuln)}
        a = _norm(answer)
        # accept full id or the DR-00x prefix
        hit = any(a == r or r.startswith(a) or a in r for r in fired) and a
        if hit:
            return True, f"Correct — {answer.strip()} fires on this attack."
        return False, ("That rule does not fire here. Hint: run "
                       f"`cyberange run {sc.id}` and read the 'alerts' line.")

    # purple
    controls = [c.strip() for c in answer.replace(";", ",").split(",") if c.strip()]
    unknown = [c for c in controls if c not in CONTROLS]
    if not controls:
        return False, "Name at least one control id."
    if unknown:
        return False, f"Unknown control(s): {', '.join(unknown)}."
    hardened = engine.run(sc, controls=controls)
    if hardened.attack_succeeded:
        return False, ("Attack still succeeds with those controls. Hint: see "
                       f"the scenario's mapped_controls via `cyberange run {sc.id}`.")
    if not hardened.final_output.startswith("[task complete]"):
        return False, "Controls broke the legitimate task (false positive)."
    return True, f"Validated — {', '.join(controls)} blocks the attack."


# --------------------------------------------------------------------------- #
# Scoreboard (per participant)
# --------------------------------------------------------------------------- #
@dataclass
class Scoreboard:
    root: str = ".cyberange/ctf"

    def __post_init__(self):
        os.makedirs(self.root, exist_ok=True)

    def _path(self, participant: str) -> str:
        safe = "".join(c for c in participant if c.isalnum() or c in "-_") or "anon"
        return os.path.join(self.root, f"{safe}.json")

    def load(self, participant: str) -> dict:
        path = self._path(participant)
        if os.path.exists(path):
            with open(path) as fh:
                return json.load(fh)
        return {"participant": participant, "solved": {}, "total": 0}

    def save(self, state: dict) -> None:
        with open(self._path(state["participant"]), "w") as fh:
            json.dump(state, fh, indent=2)

    def submit(self, participant: str, challenge_id: str, answer: str) -> SubmitResult:
        challenge = CHALLENGES.get(challenge_id)
        if not challenge:
            return SubmitResult(False, 0, f"No such challenge: {challenge_id}")
        state = self.load(participant)
        if challenge_id in state["solved"]:
            return SubmitResult(True, 0, "Already solved.", already_solved=True,
                                flag=state["solved"][challenge_id]["flag"])
        ok, message = grade(challenge, answer)
        if not ok:
            return SubmitResult(False, 0, message)
        flag = f"CYBERANGE{{{challenge_id}}}"
        state["solved"][challenge_id] = {
            "points": challenge.points, "flag": flag, "ts": time.time(),
            "track": challenge.track}
        state["total"] += challenge.points
        self.save(state)
        return SubmitResult(True, challenge.points, message, flag=flag)

    def score(self, participant: str) -> dict:
        state = self.load(participant)
        by_track = {t: 0 for t in TRACKS}
        for cid, rec in state["solved"].items():
            by_track[rec["track"]] += rec["points"]
        return {"participant": participant, "total": state["total"],
                "solved": len(state["solved"]), "of": len(CHALLENGES),
                "by_track": by_track}

    def leaderboard(self) -> list[dict]:
        rows = []
        for fn in os.listdir(self.root):
            if fn.endswith(".json"):
                with open(os.path.join(self.root, fn)) as fh:
                    s = json.load(fh)
                rows.append({"participant": s["participant"], "total": s["total"],
                             "solved": len(s["solved"])})
        return sorted(rows, key=lambda r: r["total"], reverse=True)


HINTS = {
    "red": "Run `cyberange run <SC>` (no controls) and copy the value after "
           "'attacker achieved:'.",
    "blue": "Run `cyberange run <SC>` and look at the 'alerts:' line — submit "
            "one of those rule ids.",
    "purple": "Each scenario lists its mapped_controls; submit the control ids "
              "that block it (run `cyberange run <SC> --controls <id>` to test).",
}
