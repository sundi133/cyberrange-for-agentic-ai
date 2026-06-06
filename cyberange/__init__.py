"""Cyberange — a cyber range for agentic AI security.

One shared engine, three team-specific surfaces:

    Red Team    = attack console      (break agents safely)
    Purple Team = validation workspace (prove the fix works)
    Blue Team   = detection & response (detect unsafe behavior)

The product is built around one complete loop::

    Attack -> Detect -> Fix -> Re-test -> Prove
"""

from .models import Scenario, Run, Finding, Severity

__all__ = ["Scenario", "Run", "Finding", "Severity", "__version__"]

__version__ = "0.1.0"
