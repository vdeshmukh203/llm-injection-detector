"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

Scans prompt templates, RAG pipeline inputs, and LLM application inputs for
prompt injection vulnerabilities. Implements pattern-based detectors for
instruction-override phrases, role-reassignment attacks, and context-escape
sequences.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

import sys as _sys
import pathlib as _pathlib

# Ensure the root-level module is importable when working from the src/ layout
_root = _pathlib.Path(__file__).parent.parent.parent
if str(_root) not in _sys.path:
    _sys.path.insert(0, str(_root))

from llm_injection_detector import (  # noqa: E402
    LLMInjectionDetector,
    LLMInjectionDetector as InjectionDetector,
    DetectionResult,
    Label,
    Rule,
    detect,
    detect_batch,
    analyze_rules,
    main,
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
    "main",
]
