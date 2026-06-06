"""Scenario library — the deepest part of the moat.

The first 10 agentic-AI attack scenarios from the product spec, each
mapped to the controls that defend it and the detections that catch it,
plus OWASP LLM Top 10 / MITRE ATLAS framework tags.
"""

from .library import SCENARIOS, by_id, by_category

__all__ = ["SCENARIOS", "by_id", "by_category"]
