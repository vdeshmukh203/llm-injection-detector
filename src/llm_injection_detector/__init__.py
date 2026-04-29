"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

Scans prompt templates, RAG pipeline inputs, and LLM application inputs for
prompt injection vulnerabilities using pattern-based detectors for
instruction-override phrases, role-reassignment attacks, and context-escape
sequences.

Note: The installable package is the flat module ``llm_injection_detector.py``
at the repository root, configured via ``py-modules`` in pyproject.toml.
This ``src/`` tree is kept for reference only and re-exports the same symbols.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

# Re-export public API from the installed flat module.
# When running from source, ensure the repo root is on sys.path first.
from llm_injection_detector import (  # noqa: E402
    InjectionDetector,
    LLMInjectionDetector,
    DetectionResult,
    Label,
    Rule,
    detect,
    detect_batch,
    analyze_rules,
)

__all__ = [
    "InjectionDetector",
    "LLMInjectionDetector",
    "DetectionResult",
    "Label",
    "Rule",
    "detect",
    "detect_batch",
    "analyze_rules",
]
