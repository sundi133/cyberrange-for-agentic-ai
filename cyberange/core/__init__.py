"""Cyberange shared core.

    scenario engine | tool sandbox | policy engine | trace recorder |
    detection rules | evidence store | reporting engine
"""

from .engine import ScenarioEngine
from .policy import PolicyEngine, CONTROLS
from .detections import DETECTIONS, run_detections
from .agent import SimAgent

__all__ = [
    "ScenarioEngine",
    "PolicyEngine",
    "CONTROLS",
    "DETECTIONS",
    "run_detections",
    "SimAgent",
    "LiveAgent",
]


def __getattr__(name):
    # Lazy import so the Anthropic SDK is only required when LiveAgent is used.
    if name == "LiveAgent":
        from .live_agent import LiveAgent
        return LiveAgent
    raise AttributeError(name)
