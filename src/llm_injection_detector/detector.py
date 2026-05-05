"""
Core detection engine re-exported from the top-level module.

This module exists so that the package layout under ``src/`` satisfies
standard Python packaging conventions and allows downstream tools to
import from the package namespace (``from llm_injection_detector.detector
import ...``) as well as from the flat single-file distribution.
"""

from llm_injection_detector import (  # noqa: F401
    Label,
    Rule,
    DetectionResult,
    LLMInjectionDetector,
    detect,
    detect_batch,
    analyze_rules,
)

InjectionDetector = LLMInjectionDetector  # canonical alias

# Public surface for ``from llm_injection_detector.detector import *``
__all__ = [
    "Label",
    "Rule",
    "DetectionResult",
    "LLMInjectionDetector",
    "detect",
    "detect_batch",
    "analyze_rules",
]
