"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

Scans prompt templates, RAG pipeline inputs, and LLM application code for
prompt injection vulnerabilities. Implements pattern-based detectors for
instruction-override phrases, role-reassignment attacks, and context-escape
sequences, plus an optional taint-tracking pass for static analysis of
untrusted data flows through Python LLM application code.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from .detector import InjectionDetector
from .report import DetectionReport

__all__ = ["InjectionDetector", "DetectionReport"]
