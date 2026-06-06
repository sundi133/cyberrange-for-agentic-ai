"""Findings generator (Red Team) + remediation export (Purple Team).

Turns a ``Run`` into a security finding that reads like a normal pentest
report, and exports it as a Jira / GitHub issue payload.
"""

from __future__ import annotations

from ..models import Finding, Run, Scenario, Severity


def generate_finding(scenario: Scenario, run: Run) -> Finding | None:
    """Produce a Finding when the attack succeeded; else ``None``."""
    if not run.attack_succeeded:
        return None

    cond = ", ".join(run.met_success_conditions) or "unsafe behavior"
    title = (
        f"Agent followed untrusted {scenario.attack_payload.channel} "
        f"instructions and {_humanize(run.met_success_conditions)}"
        if scenario.attack_payload
        else f"{scenario.name}: unsafe agent behavior"
    )
    description = (
        f"While performing the task \"{scenario.starting_task}\", the "
        f"{scenario.target_agent_type} ingested adversarial content via "
        f"{scenario.attack_payload.channel if scenario.attack_payload else 'input'} "
        f"and carried out attacker-controlled actions. "
        f"Triggered conditions: {cond}."
    )
    return Finding(
        title=title,
        severity=scenario.severity,
        description=description,
        impact=_impact(scenario),
        recommendation=_recommendation(scenario),
        scenario_id=scenario.id,
        run_id=run.id,
        evidence=run.evidence,
        owasp=scenario.owasp,
        mitre_atlas=scenario.mitre_atlas,
    )


def _humanize(conditions: list[str]) -> str:
    mapping = {
        "data_exfiltration": "attempted confidential data exfiltration",
        "external_email_sent": "drafted/sent an external email",
        "restricted_doc_accessed": "accessed a restricted document",
        "memory_poisoned": "persisted attacker-controlled memory",
        "shell_executed": "executed an unsafe shell command",
        "code_changed": "modified source code",
        "cross_tenant_access": "accessed another tenant's data",
        "external_post": "posted to an external channel",
        "delegated_privileged": "bypassed approval via delegation",
    }
    return "; ".join(mapping.get(c, c) for c in conditions) or "behaved unsafely"


def _impact(scenario: Scenario) -> str:
    base = {
        "prompt_injection": (
            "An attacker could use indirect prompt injection to cause the "
            "agent to leak confidential business data or take unauthorized "
            "actions."
        ),
        "rag_poisoning": (
            "Poisoned retrieval content can steer the agent toward incorrect "
            "or attacker-chosen decisions."
        ),
        "tool_abuse": (
            "Over-permissioned tools let an attacker chain actions the agent "
            "should never be able to perform."
        ),
        "memory_poisoning": (
            "Persisted malicious preferences let an attacker influence future "
            "sessions long after the initial injection."
        ),
        "secret_exfiltration": (
            "Sensitive data can be exfiltrated outside the trust boundary."
        ),
        "multi_agent": (
            "A compromised worker agent can bypass approvals on the "
            "orchestrator's behalf."
        ),
        "approval_bypass": (
            "Risky actions can be completed without the intended human "
            "approval."
        ),
    }
    return base.get(scenario.category, "Material increase in agentic AI risk.")


def _recommendation(scenario: Scenario) -> str:
    controls = ", ".join(scenario.mapped_controls) or "appropriate controls"
    return (
        "Separate instructions from data, apply least privilege to tools and "
        "documents, and require approval for high-risk outbound actions. "
        f"Validate the following controls in Cyberange Purple: {controls}."
    )


# --------------------------------------------------------------------------- #
# Ticket export (Jira / GitHub)
# --------------------------------------------------------------------------- #
def to_github_issue(finding: Finding) -> dict:
    labels = ["cyberange", f"severity:{finding.severity.value}"]
    labels += [f"owasp:{o}" for o in finding.owasp]
    return {
        "title": f"[Cyberange] {finding.title}",
        "body": finding.to_markdown(),
        "labels": labels,
    }


def to_jira_issue(finding: Finding) -> dict:
    priority = {
        Severity.CRITICAL: "Highest",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Lowest",
    }[finding.severity]
    return {
        "fields": {
            "summary": finding.title,
            "description": finding.to_markdown(),
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": ["cyberange", f"scenario-{finding.scenario_id}"],
        }
    }
