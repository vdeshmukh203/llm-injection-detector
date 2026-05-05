"""
llm_injection_detector: Static and heuristic prompt injection detector.

Scans prompt templates, RAG pipeline inputs, and LLM application inputs for
prompt injection vulnerabilities using a curated pattern library with
calibrated heuristic scoring.
"""

__version__ = "0.2.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from llm_injection_detector import (  # noqa: F401
    Label,
    Rule,
    DetectionResult,
    LLMInjectionDetector,
    detect,
    detect_batch,
    analyze_rules,
)
from .detector import InjectionDetector  # noqa: F401 (re-exported alias)
from .report import DetectionReport  # noqa: F401

__all__ = [
    "Label",
    "Rule",
    "DetectionResult",
    "LLMInjectionDetector",
    "InjectionDetector",
    "DetectionReport",
    "detect",
    "detect_batch",
    "analyze_rules",
]
