"""
llm_injection_detector – public package API.

This file re-exports the canonical public symbols from the top-level
``llm_injection_detector`` module so that both flat-module installs
(``import llm_injection_detector``) and potential src-layout installs
present an identical interface.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from llm_injection_detector import (  # noqa: F401
    LLMInjectionDetector,
    LLMInjectionDetector as InjectionDetector,
    DetectionResult,
    Label,
    Rule,
    detect,
    detect_batch,
    analyze_rules,
)

__all__ = [
    "LLMInjectionDetector",
    "InjectionDetector",
    "DetectionResult",
    "Label",
    "Rule",
    "detect",
    "detect_batch",
    "analyze_rules",
]
