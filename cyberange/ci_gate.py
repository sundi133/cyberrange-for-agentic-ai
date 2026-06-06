"""CI/CD regression gate for agentic-AI security.

Run in CI to fail the build if an agent security regression is introduced:

  * every seeded attack must still succeed against an undefended agent
    (the scenario library hasn't silently broken), and
  * every mapped control must still neutralize its scenario, and
  * detection coverage over the library must stay at 100%.

This is what lets teams add Cyberange scenarios to CI/CD as regression tests
(``Add to CI/CD`` in the Purple Team view). Exits non-zero on any failure.

    python -m cyberange.ci_gate
"""

from __future__ import annotations

import sys

from .core.engine import ScenarioEngine
from .core import report as R
from .scenarios import SCENARIOS


def main(argv: list[str] | None = None) -> int:
    engine = ScenarioEngine()
    failures: list[str] = []

    runs_vuln = []
    for sc in SCENARIOS:
        vuln = engine.run(sc, controls=[])
        runs_vuln.append(vuln)

        if not vuln.attack_succeeded:
            failures.append(f"{sc.id}: attack no longer fires undefended")
        if not vuln.detected:
            failures.append(f"{sc.id}: no detection fired on the attack")

        hardened = engine.run(sc, controls=sc.mapped_controls)
        if hardened.attack_succeeded:
            failures.append(
                f"{sc.id}: mapped controls failed to block "
                f"({hardened.met_success_conditions})"
            )
        if not hardened.final_output.startswith("[task complete]"):
            failures.append(f"{sc.id}: safe task regressed after hardening")

    coverage = R.blue_dashboard(runs_vuln)["detection_coverage_pct"]
    if coverage < 100:
        failures.append(f"detection coverage dropped to {coverage}%")

    total = len(SCENARIOS)
    if failures:
        print(f"❌ CI gate FAILED ({len(failures)} issue(s)):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"✅ CI gate passed: {total} scenarios, all controls validated, "
          f"detection coverage {coverage}%.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
