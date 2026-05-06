"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

Scans prompt templates, RAG pipeline inputs, and LLM application code for
prompt injection vulnerabilities.  Implements pattern-based detectors for
instruction-override phrases, role-reassignment attacks, and context-escape
sequences.

This ``src/`` package re-exports the public API from the canonical
``llm_injection_detector`` module (project root) so that both import paths
work correctly after installation.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from llm_injection_detector import (  # noqa: E402 – root module
    LLMInjectionDetector as InjectionDetector,
    LLMInjectionDetector,
    DetectionResult,
    DetectionResult as DetectionReport,
    Label,
    Rule,
    detect,
    detect_batch,
    analyze_rules,
)

__all__ = [
    "InjectionDetector",
    "LLMInjectionDetector",
    "DetectionReport",
    "DetectionResult",
    "Label",
    "Rule",
    "detect",
    "detect_batch",
    "analyze_rules",
]
