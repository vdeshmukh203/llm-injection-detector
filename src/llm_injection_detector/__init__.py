"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

Scans prompt templates, RAG pipeline inputs, and LLM application code for
prompt injection vulnerabilities. Implements pattern-based detectors for
instruction-override phrases, role-reassignment attacks, and context-escape
sequences.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

import sys
import pathlib

# Allow importing from the root-level module when using the src layout
_root = pathlib.Path(__file__).parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from llm_injection_detector import (  # noqa: E402
    LLMInjectionDetector as InjectionDetector,
    DetectionResult,
    Label,
    Rule,
    detect,
    detect_batch,
    analyze_rules,
)

__all__ = [
    "InjectionDetector",
    "DetectionResult",
    "Label",
    "Rule",
    "detect",
    "detect_batch",
    "analyze_rules",
]
