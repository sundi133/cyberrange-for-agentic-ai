"""Cyberange command-line interface.

    cyberange list
    cyberange run SC-001 [--controls a,b]
    cyberange loop SC-001              # Attack -> Detect -> Fix -> Re-test -> Prove
    cyberange matrix                   # Control Validation Matrix (Purple)
    cyberange blue                     # Blue Team dashboard over all scenarios
    cyberange report                   # Executive / GRC summary
    cyberange replay <run_id>
"""

from __future__ import annotations

import argparse
import json
import sys

from .core.detections import run_detections
from .core.engine import ScenarioEngine
from .core.evidence import EvidenceStore
from .core.findings import generate_finding, to_github_issue, to_jira_issue
from .core import report as R
from .core import integrations
from .core.validation import build_matrix
from .scenarios import SCENARIOS, by_id


def _engine(live: bool = False) -> ScenarioEngine:
    """Build an engine backed by the simulator or a real Claude agent."""
    if live:
        from .core import LiveAgent  # lazy: needs the Anthropic SDK + API key
        return ScenarioEngine(agent=LiveAgent())
    return ScenarioEngine()


C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "purple": "\033[95m", "bold": "\033[1m",
    "dim": "\033[2m", "end": "\033[0m",
}


def _c(text, color):
    return f"{C[color]}{text}{C['end']}"


# --------------------------------------------------------------------------- #
def cmd_list(_args):
    print(_c("Cyberange scenario library", "bold"))
    for s in SCENARIOS:
        print(
            f"  {_c(s.id, 'bold')}  {s.name}\n"
            f"      {_c(s.category, 'dim')} | severity={s.severity.value} | "
            f"controls={','.join(s.mapped_controls)}"
        )


def cmd_run(args):
    sc = by_id(args.scenario)
    controls = args.controls.split(",") if args.controls else []
    engine = _engine(getattr(args, "live", False))
    run = engine.run(sc, controls=controls)
    _print_run(sc, run)


def cmd_loop(args):
    """The product's core loop, end to end."""
    sc = by_id(args.scenario)
    engine = _engine(getattr(args, "live", False))
    store = EvidenceStore()

    print(_c(f"\n=== Cyberange loop: {sc.id} {sc.name} ===", "bold"))

    # 1) ATTACK (Red) ---------------------------------------------------- #
    print(_c("\n[1] ATTACK  (Red Team)", "red"))
    before = engine.run(sc, controls=[])
    store.save_run(before)
    _print_run(sc, before, brief=True)
    finding = generate_finding(sc, before)
    if finding:
        store.save_finding(finding)
        print(_c("    Finding generated:", "red"), finding.title)

    # 2) DETECT (Blue) --------------------------------------------------- #
    print(_c("\n[2] DETECT  (Blue Team)", "blue"))
    if before.alerts:
        for a in before.alerts:
            print(f"    ALERT {a.rule_id} [{a.severity.value}] {a.title}")
    else:
        print("    (no detections)")

    # 3) FIX (Purple maps controls) -------------------------------------- #
    print(_c("\n[3] FIX  (apply mapped controls)", "purple"))
    print(f"    controls: {', '.join(sc.mapped_controls)}")

    # 4) RE-TEST (Purple) ------------------------------------------------ #
    print(_c("\n[4] RE-TEST  (Purple Team)", "purple"))
    comparison = engine.re_test(sc)
    store.save_run(comparison.after)
    _print_run(sc, comparison.after, brief=True)

    # 5) PROVE ----------------------------------------------------------- #
    print(_c("\n[5] PROVE", "green"))
    s = comparison.summary()
    status = s["control_status"]
    color = "green" if status == "validated" else "yellow" if "fixed" in status else "red"
    print(f"    before={s['before']}  ->  after={s['after']}")
    print(f"    fixed={s['fixed']}  detection_fired={s['detection_fired']}  "
          f"safe_task_preserved={s['safe_task_preserved']}")
    print(_c(f"    CONTROL STATUS: {status.upper()}", color))


def cmd_matrix(_args):
    matrix = build_matrix(SCENARIOS)
    print(_c("Control Validation Matrix", "bold"), _c("(Purple Team)", "purple"))
    for cid, cv in matrix.items():
        print(f"\n{_c(cid, 'bold')}  (passed {cv.passed} / failed {cv.failed})")
        for r in cv.results:
            if r.status == "not_tested":
                continue
            mark = _c("PASS", "green") if r.status == "passed" else _c("FAIL", "red")
            print(f"  [{mark}] {r.scenario_id} {r.scenario_name}")


def cmd_blue(_args):
    engine = ScenarioEngine()
    runs = [engine.run(s, controls=[]) for s in SCENARIOS]
    dash = R.blue_dashboard(runs)
    print(_c("Blue Team dashboard", "blue"))
    print(f"  detection coverage: {dash['detection_coverage_pct']}%")
    print(f"  blocked actions:    {dash['blocked_actions']}")
    print(f"  sensitive touches:  {dash['sensitive_data_touches']}")
    print(f"  MTTD: {dash['mean_time_to_detect_s']}s  "
          f"MTTC: {dash['mean_time_to_contain_s']}s")
    print("  live risk events:")
    for e in dash["live_risk_events"]:
        print(f"    {e['scenario_id']} [{e['severity']}] -> "
              f"{', '.join(e['alerts'])}")


def cmd_report(_args):
    engine = ScenarioEngine()
    comparisons = [engine.re_test(s) for s in SCENARIOS]
    print(R.executive_summary(comparisons))


def cmd_replay(args):
    store = EvidenceStore()
    print(json.dumps(store.replay(args.run_id), indent=2, default=str))


def cmd_export(args):
    sc = by_id(args.scenario)
    engine = ScenarioEngine()
    run = engine.run(sc, controls=[])
    finding = generate_finding(sc, run)
    if not finding:
        print("No finding (attack did not succeed).")
        return
    print(json.dumps(to_github_issue(finding), indent=2))


def cmd_push(args):
    """Deliver a scenario's finding/alerts to a real external system."""
    sc = by_id(args.scenario)
    run = ScenarioEngine().run(sc, controls=[])
    target = args.target

    # Build the payload (independent of whether the target is configured).
    if target == "siem":
        payload = R.siem_event(run)
        action = lambda: integrations.send_siem(payload)
    else:
        finding = generate_finding(sc, run)
        if not finding:
            print("No finding to push (attack did not succeed).")
            return
        if target == "github":
            payload = to_github_issue(finding)
            action = lambda: integrations.create_github_issue(payload)
        else:  # jira
            payload = to_jira_issue(finding)
            action = lambda: integrations.create_jira_issue(payload)

    if args.dry_run:
        print(_c(f"[dry-run] would POST to {target}:", "dim"))
        print(json.dumps(payload, indent=2)[:1200])
        return

    if not integrations.configured(target):
        print(_c(f"Target '{target}' is not configured.", "yellow"))
        print("Set the required env vars (see README), or use --dry-run.")
        return

    try:
        result = action()
    except integrations.IntegrationError as e:
        print(_c(f"[FAIL] {target}: {e}", "red"))
        return
    color = "green" if result.ok else "red"
    print(_c(str(result), color))


# --------------------------------------------------------------------------- #
def _print_run(sc, run, brief=False):
    color = "red" if run.attack_succeeded else "green"
    print(f"  status: {_c(run.status.value, color)}  "
          f"controls={run.controls or '[]'}")
    if run.met_success_conditions:
        print(f"  attacker achieved: {', '.join(run.met_success_conditions)}")
    if not brief:
        print("  reasoning trace:")
        for step in run.reasoning_trace:
            print(f"    - {step}")
    print("  tool calls: " + ", ".join(
        f"{tc.tool}:{tc.args.get('arg','')}" + (" [BLOCKED]" if tc.blocked else "")
        for tc in run.tool_calls) or "  tool calls: (none)")
    if run.alerts:
        print("  alerts: " + ", ".join(a.rule_id for a in run.alerts))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cyberange", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list scenarios").set_defaults(func=cmd_list)

    pr = sub.add_parser("run", help="run a scenario")
    pr.add_argument("scenario")
    pr.add_argument("--controls", default="")
    pr.add_argument("--live", action="store_true",
                    help="attack a real Claude agent (needs ANTHROPIC_API_KEY)")
    pr.set_defaults(func=cmd_run)

    pl = sub.add_parser("loop", help="full attack->prove loop")
    pl.add_argument("scenario")
    pl.add_argument("--live", action="store_true",
                    help="drive a real Claude agent instead of the simulator")
    pl.set_defaults(func=cmd_loop)

    sub.add_parser("matrix", help="control validation matrix").set_defaults(func=cmd_matrix)
    sub.add_parser("blue", help="blue team dashboard").set_defaults(func=cmd_blue)
    sub.add_parser("report", help="executive summary").set_defaults(func=cmd_report)

    pe = sub.add_parser("export", help="export finding as GitHub issue")
    pe.add_argument("scenario")
    pe.set_defaults(func=cmd_export)

    pp = sub.add_parser("push", help="deliver finding/alerts to a real system")
    pp.add_argument("scenario")
    pp.add_argument("target", choices=["siem", "github", "jira"])
    pp.add_argument("--dry-run", action="store_true",
                    help="print the payload instead of sending it")
    pp.set_defaults(func=cmd_push)

    prp = sub.add_parser("replay", help="replay a stored run")
    prp.add_argument("run_id")
    prp.set_defaults(func=cmd_replay)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
