"""Enterprise-safe mock tool sandbox.

These are *fake* tools: email, docs, browser, Slack, GitHub, memory and a
shell. Nothing leaves the process, so attack scenarios can run safely in
CI/CD or on a laptop. Each tool returns a structured result and records
whether the data it touched was sensitive or untrusted, which is what the
policy engine and detection rules reason over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    classification: str = "public"  # public | internal | restricted
    note: str = ""


@dataclass
class ToolSandbox:
    """A sandboxed environment seeded from ``Scenario.seed_data``.

    The sandbox is intentionally dumb: it just stores documents, sent
    messages, memory writes and a fake shell transcript. All security
    judgement lives in the policy engine and detection rules, so the same
    sandbox is reused for vulnerable and hardened runs.
    """

    documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    sent_messages: list[dict[str, Any]] = field(default_factory=list)
    memory: dict[str, dict[str, Any]] = field(default_factory=dict)
    shell_log: list[str] = field(default_factory=list)
    github_actions: list[dict[str, Any]] = field(default_factory=list)
    slack_posts: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    @classmethod
    def from_seed(cls, seed: dict[str, Any]) -> "ToolSandbox":
        sb = cls()
        for doc in seed.get("documents", []):
            sb.documents[doc["doc_id"]] = dict(doc)
        for key, val in seed.get("memory", {}).items():
            sb.memory[key] = {"value": val, "source": "user"}
        return sb

    # ----- docs / RAG -------------------------------------------------- #
    def search_docs(self, query: str) -> ToolResult:
        hits = [
            {
                "doc_id": d["doc_id"],
                "title": d.get("title", d["doc_id"]),
                "classification": d.get("classification", "public"),
                "untrusted": d.get("untrusted", False),
                "snippet": d.get("content", "")[:160],
            }
            for d in self.documents.values()
            if query.lower() in (d.get("title", "") + d.get("content", "")).lower()
            or query == "*"
        ]
        return ToolResult(ok=True, data=hits, note=f"{len(hits)} hit(s)")

    def read_doc(self, doc_id: str) -> ToolResult:
        doc = self.documents.get(doc_id)
        if not doc:
            return ToolResult(ok=False, note="not found")
        return ToolResult(
            ok=True,
            data=doc.get("content", ""),
            classification=doc.get("classification", "public"),
        )

    # ----- email / slack ---------------------------------------------- #
    def send_email(self, to: str, subject: str, body: str) -> ToolResult:
        external = not to.endswith("@acme.internal")
        msg = {"to": to, "subject": subject, "body": body, "external": external}
        self.sent_messages.append(msg)
        return ToolResult(ok=True, data=msg, note="external" if external else "internal")

    def post_slack(self, channel: str, text: str) -> ToolResult:
        post = {"channel": channel, "text": text}
        self.slack_posts.append(post)
        return ToolResult(ok=True, data=post)

    # ----- memory ------------------------------------------------------ #
    def write_memory(self, key: str, value: str, source: str) -> ToolResult:
        self.memory[key] = {"value": value, "source": source}
        return ToolResult(ok=True, data={key: value})

    # ----- browser ----------------------------------------------------- #
    def fetch_url(self, url: str) -> ToolResult:
        page = self.documents.get(url)
        if not page:
            return ToolResult(ok=False, note="404")
        return ToolResult(
            ok=True,
            data=page.get("content", ""),
            classification="public",
            note="untrusted_web",
        )

    # ----- github ------------------------------------------------------ #
    def github_change(self, repo: str, path: str, patch: str) -> ToolResult:
        action = {"repo": repo, "path": path, "patch": patch}
        self.github_actions.append(action)
        return ToolResult(ok=True, data=action)

    # ----- shell ------------------------------------------------------- #
    def run_shell(self, command: str) -> ToolResult:
        self.shell_log.append(command)
        return ToolResult(ok=True, data=f"$ {command}\n(simulated)")


# The mock tools advertised in the MVP spec.
MOCK_TOOLS = [
    "search_docs",
    "read_doc",
    "send_email",
    "post_slack",
    "write_memory",
    "fetch_url",
    "github_change",
    "run_shell",
]
