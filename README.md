# ⛁ Cyberange — a cyber range for agentic AI

Cyberange is a shared platform for **Red**, **Purple**, and **Blue** teams to
safely attack, defend, and prove the security of AI agents. It is built around
**one shared engine** with **three team-specific surfaces**, and the whole
product revolves around a single loop:

```
Attack → Detect → Fix → Re-test → Prove
```

> Red finds the failure. Blue builds the defense. Purple proves the defense works.

The core, CLI, and test suite have **zero third-party dependencies** — every
attack runs in a deterministic, offline, enterprise-safe mock environment, so
scenarios are reproducible and CI/CD friendly.

---

## The three surfaces

| Surface | Question it answers | What it does |
| --- | --- | --- |
| **Red Team** | *Can we break it?* | Run adversarial scenarios, capture replayable traces, generate findings. |
| **Purple Team** | *Did the fix work?* | Re-test, before/after comparison, **Control Validation Matrix**. |
| **Blue Team** | *Can we detect / respond?* | Detection rules, alerts, SIEM export, coverage & MTTD/MTTC. |

All three read from the **Shared Core**: scenario engine · mock tool sandbox ·
policy engine · trace recorder · detection rules · evidence store · reporting.

---

## Quick start

No install required for the core experience:

```bash
# List the built-in scenario library
python -m cyberange.cli list

# Run the full product loop on one scenario
python -m cyberange.cli loop SC-001

# Prove every control works (Purple Team killer feature)
python -m cyberange.cli matrix

# Blue Team detection dashboard across all scenarios
python -m cyberange.cli blue

# Executive / GRC report
python -m cyberange.cli report

# Export a finding as a GitHub issue
python -m cyberange.cli export SC-001
```

### Web dashboard + HTTP API (optional)

```bash
pip install -r requirements.txt
uvicorn cyberange.api:app --reload
# open http://127.0.0.1:8000  → Red / Purple / Blue tabs
```

### Tests

```bash
pip install pytest
pytest -q          # 65 tests, ~0.1s
```

---

## The loop, end to end (`loop SC-001`)

```
[1] ATTACK  (Red)    malicious customer email → agent reads restricted pricing → drafts external email
[2] DETECT  (Blue)   DR-001 injection→sensitive · DR-002 tool chain · DR-003 egress
[3] FIX              apply mapped controls (untrusted_content_separation, dlp_egress, …)
[4] RE-TEST (Purple) same scenario, controls on → attack blocked, safe task still completes
[5] PROVE            before=attack_succeeded → after=attack_blocked → CONTROL STATUS: VALIDATED
```

---

## Scenario library (the moat)

Ten agentic-AI attack scenarios, each mapped to defending controls, catching
detections, and OWASP LLM Top 10 / MITRE ATLAS tags:

| ID | Scenario | Category |
| --- | --- | --- |
| SC-001 | Email prompt injection causing data access | prompt_injection |
| SC-002 | PDF prompt injection causing secret access | prompt_injection |
| SC-003 | Webpage prompt injection causing external post | prompt_injection |
| SC-004 | RAG poisoning causing a wrong decision | rag_poisoning |
| SC-005 | Memory poisoning through an untrusted source | memory_poisoning |
| SC-006 | Agent sends sensitive data externally | secret_exfiltration |
| SC-007 | Agent accesses a cross-tenant document | tool_abuse |
| SC-008 | Agent executes an unsafe shell command | tool_abuse |
| SC-009 | Malicious GitHub issue changes code | tool_abuse |
| SC-010 | Multi-agent delegation bypasses approval | multi_agent |

---

## Architecture

```
cyberange/
├── models.py            # Scenario · Run · Finding (zero-dep dataclasses)
├── scenarios/           # the scenario library (the moat)
├── core/
│   ├── engine.py        # scenario runner + re-test/comparison
│   ├── agent.py         # SimAgent — deterministic agent under test
│   ├── tools.py         # enterprise-safe mock tool sandbox
│   ├── policy.py        # policy engine + toggleable control catalog
│   ├── detections.py    # Blue Team detection rules
│   ├── findings.py      # Red Team findings + Jira/GitHub export
│   ├── validation.py    # Purple Team Control Validation Matrix
│   ├── evidence.py      # replayable run/finding evidence store
│   └── report.py        # red/blue/purple dashboards + SIEM export
├── cli.py               # command-line interface
└── api.py               # optional FastAPI surface
web/index.html           # single-page Red/Purple/Blue dashboard
tests/                   # pytest suite
```

### Data model

`Scenario` (objective, attacker goal, payload, success conditions, mapped
controls, detection rules, framework tags) → `Run` (tool calls, retrieved
context, memory/policy events, alerts, evidence, replayable trace) →
`Finding` (title, severity, impact, recommendation, evidence).

---

## Extending Cyberange

- **New attack:** add a `Scenario` to `cyberange/scenarios/library.py` with an
  `AttackPayload` whose `intents` describe what a hijacked agent would do.
- **New control:** add a `Control` to `CONTROLS` in `cyberange/core/policy.py`.
- **New detection:** add a `DetectionRule` to `DETECTIONS` in
  `cyberange/core/detections.py`.

A new scenario is automatically picked up by the CLI, API, matrix, and
dashboards.

## Safety

Every tool is a **mock** — nothing leaves the process. There is no real email,
shell, network egress, or code modification. Cyberange is designed for
authorized security testing of your own agents.
