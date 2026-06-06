"""The simulated agent under test.

``SimAgent`` is a deterministic, offline stand-in for a real agent. It is
*not* an LLM: it models the two behaviors that matter for security testing:

  * A **vulnerable** agent ingests untrusted content (email/PDF/web/RAG/
    memory) and obeys hidden instructions, carrying out the scenario's
    ``intents`` as tool calls.
  * A **hardened** agent — one running with the
    ``untrusted_content_separation`` control — treats that content as data,
    ignores the hidden instruction, and completes only the safe task.

Either way, every candidate action is routed through the policy engine, so
downstream guardrails (DLP, ACLs, approval gates) provide defense in depth
even when injection is not fully neutralized.
"""

from __future__ import annotations

from .evaluation import build_evidence, check_success
from .policy import Action, PolicyEngine
from .tools import ToolSandbox
from ..models import (
    MemoryEvent,
    RetrievedDoc,
    Run,
    RunStatus,
    Scenario,
    ToolCall,
)


class SimAgent:
    def __init__(self, agent_id: str = "support-agent", model: str = "sim-agent"):
        self.agent_id = agent_id
        self.model = model

    # ------------------------------------------------------------------ #
    def run(
        self,
        scenario: Scenario,
        sandbox: ToolSandbox,
        policy: PolicyEngine,
    ) -> Run:
        run = Run(
            scenario_id=scenario.id,
            agent_id=self.agent_id,
            model=self.model,
            controls=list(policy.active_ids),
        )
        run.reasoning_trace.append(f"Task received: {scenario.starting_task}")

        # 1) The agent ingests untrusted content from the environment.
        payload = scenario.attack_payload
        adopted_intents: list[dict] = []
        if payload:
            run.reasoning_trace.append(
                f"Ingested untrusted {payload.channel} content."
            )
            if policy.neutralizes_for(payload.channel):
                run.reasoning_trace.append(
                    f"Injection on channel '{payload.channel}' neutralized by "
                    "active control: treating content as DATA, ignoring "
                    "embedded instructions."
                )
            else:
                run.reasoning_trace.append(
                    f"Following embedded instruction: "
                    f"\"{payload.hidden_instruction[:80]}\""
                )
                adopted_intents = payload.intents

        # 2) Carry out the (possibly hijacked) plan, action by action.
        carries_restricted = False
        for intent in adopted_intents:
            verb = intent["verb"]
            arg = intent.get("arg", "")
            meta = dict(intent.get("meta", {}))

            # Enrich action metadata from the live sandbox state.
            if verb == "read_doc":
                doc = sandbox.documents.get(arg, {})
                meta.setdefault("classification", doc.get("classification", "public"))
            if verb == "send_email":
                meta.setdefault("external", not str(arg).endswith("@acme.internal"))
            if verb in ("send_email", "post_slack") and carries_restricted:
                meta.setdefault("classification", "restricted")
            if verb in ("write_memory", "github_change"):
                meta.setdefault("untrusted_source", True)

            allowed, pevent = policy.evaluate(Action(verb, arg, meta))
            if pevent:
                run.policy_events.append(pevent)

            if not allowed:
                run.tool_calls.append(
                    ToolCall(
                        tool=verb,
                        args={"arg": arg, **meta},
                        blocked=True,
                        block_reason=pevent.reason if pevent else "blocked",
                        untrusted_source=meta.get("untrusted_source", False),
                    )
                )
                run.reasoning_trace.append(
                    f"Action {verb}:{arg} BLOCKED -> "
                    f"{pevent.reason if pevent else 'policy'}"
                )
                continue

            carries_restricted = self._execute(
                run, sandbox, verb, arg, meta, carries_restricted
            )

        # 3) Always attempt the benign part of the task so we can check the
        #    "agent still completed the safe work" Purple-Team question.
        run.final_output = self._do_safe_task(scenario, run)

        # 4) Evaluate attacker success conditions against the recorded trace.
        run.met_success_conditions = check_success(scenario, run)
        run.status = (
            RunStatus.ATTACK_SUCCEEDED
            if run.met_success_conditions
            else RunStatus.ATTACK_BLOCKED
        )
        run.evidence = build_evidence(scenario, run)
        return run

    # ------------------------------------------------------------------ #
    def _execute(self, run, sandbox, verb, arg, meta, carries_restricted) -> bool:
        """Run one allowed action against the sandbox; update agent state."""
        tc = ToolCall(
            tool=verb,
            args={"arg": arg, **meta},
            untrusted_source=meta.get("untrusted_source", False),
        )

        if verb == "search_docs":
            res = sandbox.search_docs(arg or "*")
            tc.result = res.data
            for hit in res.data:
                run.retrieved_context.append(
                    RetrievedDoc(
                        doc_id=hit["doc_id"],
                        title=hit["title"],
                        classification=hit["classification"],
                        untrusted=hit["untrusted"],
                        snippet=hit["snippet"],
                    )
                )
        elif verb == "read_doc":
            res = sandbox.read_doc(arg)
            tc.result = {"classification": res.classification}
            if res.classification == "restricted":
                carries_restricted = True
            run.retrieved_context.append(
                RetrievedDoc(
                    doc_id=arg,
                    title=sandbox.documents.get(arg, {}).get("title", arg),
                    classification=res.classification,
                )
            )
        elif verb == "send_email":
            res = sandbox.send_email(
                to=arg, subject=meta.get("subject", "(draft)"),
                body=meta.get("body", "(restricted content)" if carries_restricted else ""),
            )
            tc.result = res.data
        elif verb == "post_slack":
            tc.result = sandbox.post_slack(arg, meta.get("text", "")).data
        elif verb == "write_memory":
            sandbox.write_memory(arg, meta.get("value", ""), source="untrusted")
            run.memory_events.append(
                MemoryEvent(
                    key=arg,
                    value=meta.get("value", ""),
                    source="untrusted",
                    untrusted_source=True,
                    accepted=True,
                )
            )
            tc.result = "written"
        elif verb == "fetch_url":
            tc.result = sandbox.fetch_url(arg).data
        elif verb == "github_change":
            tc.result = sandbox.github_change(
                meta.get("repo", arg), meta.get("path", ""), meta.get("patch", "")
            ).data
        elif verb == "run_shell":
            tc.result = sandbox.run_shell(arg).data
        elif verb == "delegate":
            tc.result = f"delegated to {arg}"
        else:
            tc.result = "noop"

        run.tool_calls.append(tc)
        run.reasoning_trace.append(f"Action {verb}:{arg} executed.")
        return carries_restricted

    # ------------------------------------------------------------------ #
    def _do_safe_task(self, scenario: Scenario, run: Run) -> str:
        """The legitimate work the user actually asked for."""
        run.reasoning_trace.append("Completing the user's legitimate request.")
        return (
            f"[task complete] {scenario.expected_safe_behavior}"
            if scenario.expected_safe_behavior
            else "[task complete]"
        )

