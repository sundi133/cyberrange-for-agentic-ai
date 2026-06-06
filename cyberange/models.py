"""Core data model for Cyberange.

The three primary entities mirror the product spec:

    Scenario  -- a reusable, replayable agentic-AI attack definition.
    Run       -- a single execution of a scenario against an agent.
    Finding   -- a security finding generated from one or more runs.

Everything is plain ``dataclasses`` so the core has zero third-party
dependencies and serializes cleanly to JSON for the API / evidence store.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, enum.Enum):
    """Standard security-finding severities."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value)


class RunStatus(str, enum.Enum):
    """Outcome of a scenario run, from the defender's point of view."""

    # The attacker achieved its goal -> a control failed.
    ATTACK_SUCCEEDED = "attack_succeeded"
    # The agent stayed safe -> controls held.
    ATTACK_BLOCKED = "attack_blocked"
    # The agent errored out before resolving.
    ERROR = "error"


class TeamSurface(str, enum.Enum):
    RED = "red"
    PURPLE = "purple"
    BLUE = "blue"


# --------------------------------------------------------------------------- #
# Trace primitives -- the replayable record of agent behavior
# --------------------------------------------------------------------------- #
@dataclass
class ToolCall:
    """A single tool invocation made by the agent."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    blocked: bool = False
    block_reason: str | None = None
    untrusted_source: bool = False
    ts: float = field(default_factory=time.time)


@dataclass
class RetrievedDoc:
    """A document surfaced into the agent context (RAG / search)."""

    doc_id: str
    title: str
    classification: str = "public"  # public | internal | restricted
    untrusted: bool = False
    snippet: str = ""


@dataclass
class MemoryEvent:
    """A write to (or rejected write to) the agent's long-term memory."""

    key: str
    value: str
    source: str = "user"
    untrusted_source: bool = False
    accepted: bool = True
    reason: str | None = None


@dataclass
class PolicyEvent:
    """A decision made by the policy engine about a candidate action."""

    policy: str
    action: str
    decision: str  # allow | block
    reason: str = ""


@dataclass
class Alert:
    """A detection raised by the Blue Team detection rules."""

    rule_id: str
    title: str
    severity: Severity = Severity.MEDIUM
    signal: list[str] = field(default_factory=list)
    recommended_response: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)


# --------------------------------------------------------------------------- #
# Scenario
# --------------------------------------------------------------------------- #
@dataclass
class AttackPayload:
    """The adversarial content injected into the environment.

    ``intents`` is the deterministic representation of the hidden
    instruction: the discrete actions a *vulnerable* agent would carry out
    if it obeyed the injected text. Keeping this explicit makes runs
    reproducible and offline (no live LLM required).
    """

    channel: str  # email | pdf | webpage | rag | memory | github | tool
    visible_content: str = ""
    hidden_instruction: str = ""
    # Each intent: {"verb": str, "arg": str, "meta": {...}} -- the discrete
    # actions a vulnerable agent performs when it obeys the hidden text.
    intents: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Scenario:
    """A reusable agentic-AI attack scenario (see spec data model)."""

    id: str
    name: str
    objective: str
    attacker_goal: str
    target_agent_type: str
    starting_task: str
    category: str  # prompt_injection | rag_poisoning | tool_abuse | ...
    severity: Severity = Severity.MEDIUM

    environment: dict[str, Any] = field(default_factory=dict)
    tools: list[str] = field(default_factory=list)
    seed_data: dict[str, Any] = field(default_factory=dict)

    attack_payload: AttackPayload | None = None
    expected_safe_behavior: str = ""
    attacker_success_conditions: list[str] = field(default_factory=list)

    detection_rules: list[str] = field(default_factory=list)
    mapped_controls: list[str] = field(default_factory=list)

    # Framework mappings strengthen the "prove control" story (GRC moat).
    owasp: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
@dataclass
class Run:
    """A single execution of a scenario against an agent."""

    scenario_id: str
    agent_id: str
    model: str = "sim-agent"
    controls: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)
    status: RunStatus = RunStatus.ATTACK_BLOCKED

    tool_calls: list[ToolCall] = field(default_factory=list)
    retrieved_context: list[RetrievedDoc] = field(default_factory=list)
    memory_events: list[MemoryEvent] = field(default_factory=list)
    policy_events: list[PolicyEvent] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)

    reasoning_trace: list[str] = field(default_factory=list)
    final_output: str = ""
    met_success_conditions: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    # ----- convenience accessors used by detections / reporting ----------- #
    @property
    def attack_succeeded(self) -> bool:
        return self.status == RunStatus.ATTACK_SUCCEEDED

    @property
    def detected(self) -> bool:
        return len(self.alerts) > 0

    @property
    def blocked_actions(self) -> list[ToolCall]:
        return [tc for tc in self.tool_calls if tc.blocked]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        for a in d["alerts"]:
            a["severity"] = (
                a["severity"].value
                if isinstance(a["severity"], Severity)
                else a["severity"]
            )
        return d


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A security finding, formatted like a normal pentest finding."""

    title: str
    severity: Severity
    description: str
    impact: str
    recommendation: str
    scenario_id: str
    run_id: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    evidence: dict[str, Any] = field(default_factory=dict)
    owner: str = "unassigned"
    status: str = "open"  # open | in_progress | remediated | accepted_risk
    owasp: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def to_markdown(self) -> str:
        ev = "\n".join(f"- {k}: {v}" for k, v in self.evidence.items())
        frameworks = ""
        if self.owasp or self.mitre_atlas:
            frameworks = (
                f"\n**Frameworks:** "
                f"{', '.join(self.owasp + self.mitre_atlas)}\n"
            )
        return (
            f"### Finding: {self.title}\n\n"
            f"**Severity:** {self.severity.value.title()}\n"
            f"{frameworks}\n"
            f"**Description**\n\n{self.description}\n\n"
            f"**Business impact**\n\n{self.impact}\n\n"
            f"**Evidence**\n\n{ev}\n\n"
            f"**Recommendation**\n\n{self.recommendation}\n"
        )
