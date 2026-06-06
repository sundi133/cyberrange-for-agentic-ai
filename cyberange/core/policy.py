"""Policy engine + control catalog.

A *control* is a defensive mitigation a Blue / Purple team turns on. The
policy engine evaluates each candidate agent action against the set of
active controls and returns an allow/block decision plus a ``PolicyEvent``
for the trace.

Actions are represented as ``Action(verb, arg, meta)`` where ``verb`` is one
of a small fixed vocabulary the agent and scenarios share (see
``cyberange/scenarios``). This keeps runs deterministic and offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..models import PolicyEvent


@dataclass
class Action:
    verb: str
    arg: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Control:
    """A toggleable defensive control."""

    id: str
    name: str
    description: str
    # Returns a block-reason string if this control blocks the action,
    # else None.
    blocks: Callable[[Action], str | None]
    # If True, the control prevents the agent from *adopting* injected
    # instructions on ANY channel (root-cause fix vs. downstream guard).
    neutralizes_injection: bool = False
    # Channels for which this control neutralizes injection (e.g. a trusted-
    # retrieval control neutralizes "rag" but nothing else).
    neutralizes_channels: frozenset[str] = frozenset()


def _restricted(action: Action) -> bool:
    return action.meta.get("classification") == "restricted"


def _external(action: Action) -> bool:
    return bool(action.meta.get("external"))


def _untrusted(action: Action) -> bool:
    return bool(action.meta.get("untrusted_source"))


# --------------------------------------------------------------------------- #
# Control catalog -- the building blocks of the Control Validation Matrix.
# --------------------------------------------------------------------------- #
_CONTROL_LIST = [
    Control(
        id="untrusted_content_separation",
        name="Untrusted content separation",
        description=(
            "Treat tool/document/web/email content as data, never as "
            "instructions. Neutralizes indirect prompt injection at the root."
        ),
        blocks=lambda a: None,
        neutralizes_injection=True,
    ),
    Control(
        id="trusted_retrieval_only",
        name="Trusted retrieval only",
        description=(
            "Restrict RAG to provenance-verified sources and deny reads of "
            "untrusted documents. Neutralizes retrieval (RAG) poisoning."
        ),
        blocks=lambda a: (
            "read of untrusted document denied"
            if a.verb == "read_doc" and _untrusted(a)
            else None
        ),
        neutralizes_channels=frozenset({"rag"}),
    ),
    Control(
        id="external_post_approval",
        name="External post approval required",
        description="Require approval before posting to external channels.",
        blocks=lambda a: (
            "external post requires approval"
            if a.verb == "post_slack" and not a.meta.get("internal")
            else None
        ),
    ),
    Control(
        id="external_email_approval",
        name="External email approval required",
        description="Require human approval before sending external email.",
        blocks=lambda a: (
            "external email requires approval"
            if a.verb == "send_email" and _external(a)
            else None
        ),
    ),
    Control(
        id="dlp_egress",
        name="DLP on outbound actions",
        description="Block egress of restricted/sensitive content.",
        blocks=lambda a: (
            "DLP: restricted content blocked from egress"
            if a.verb in ("send_email", "post_slack") and _restricted(a)
            else None
        ),
    ),
    Control(
        id="restricted_doc_acl",
        name="Least-privilege document access",
        description=(
            "Deny access to restricted documents from workflows that do not "
            "require them."
        ),
        blocks=lambda a: (
            "access to restricted document denied for this workflow"
            if a.verb == "read_doc" and _restricted(a)
            else None
        ),
    ),
    Control(
        id="memory_write_approval",
        name="Memory-write approval",
        description="Reject long-term memory writes from untrusted sources.",
        blocks=lambda a: (
            "memory write from untrusted source rejected"
            if a.verb == "write_memory" and _untrusted(a)
            else None
        ),
    ),
    Control(
        id="tool_permission_model",
        name="Tool permission model",
        description="Restrict high-risk tools (e.g. shell) by default.",
        blocks=lambda a: (
            "tool 'run_shell' not permitted for this agent"
            if a.verb == "run_shell"
            else None
        ),
    ),
    Control(
        id="cross_tenant_isolation",
        name="Cross-tenant isolation",
        description="Deny document access outside the active tenant.",
        blocks=lambda a: (
            "cross-tenant document access denied"
            if a.verb == "read_doc" and a.meta.get("cross_tenant")
            else None
        ),
    ),
    Control(
        id="code_change_review",
        name="Code-change review gate",
        description=(
            "Require review/approval before an agent modifies code from an "
            "untrusted issue/PR."
        ),
        blocks=lambda a: (
            "code change from untrusted source requires review"
            if a.verb == "github_change" and _untrusted(a)
            else None
        ),
    ),
    Control(
        id="delegation_approval",
        name="Multi-agent handoff approval",
        description=(
            "Validate delegation/handoff rules so a worker agent cannot "
            "bypass approval on the orchestrator's behalf."
        ),
        blocks=lambda a: (
            "delegated privileged action requires approval"
            if a.verb == "delegate" and a.meta.get("privileged")
            else None
        ),
    ),
]

CONTROLS: dict[str, Control] = {c.id: c for c in _CONTROL_LIST}


class PolicyEngine:
    """Evaluates actions against a set of active controls."""

    def __init__(self, active: list[str] | None = None):
        self.active_ids = list(active or [])
        self.active = [CONTROLS[c] for c in self.active_ids if c in CONTROLS]

    @property
    def neutralizes_injection(self) -> bool:
        return any(c.neutralizes_injection for c in self.active)

    def neutralizes_for(self, channel: str) -> bool:
        """Is injection on ``channel`` neutralized by an active control?"""
        return any(
            c.neutralizes_injection or channel in c.neutralizes_channels
            for c in self.active
        )

    def evaluate(self, action: Action) -> tuple[bool, PolicyEvent | None]:
        """Return ``(allowed, policy_event_or_None)``."""
        for control in self.active:
            reason = control.blocks(action)
            if reason:
                return False, PolicyEvent(
                    policy=control.id,
                    action=f"{action.verb}:{action.arg}",
                    decision="block",
                    reason=reason,
                )
        return True, None
