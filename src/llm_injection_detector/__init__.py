"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

Re-exports the public API from the root module so that both import styles work:

    import llm_injection_detector as lid          # root module (installed as py-module)
    from llm_injection_detector import detect     # same
"""

import sys
import os

# Make the repo root importable when this package is used from the src/ layout.
_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _root not in sys.path:
    sys.path.insert(0, _root)

from llm_injection_detector import (  # noqa: E402
    __version__,
    __author__,
    __license__,
    Label,
    Rule,
    DetectionResult,
    LLMInjectionDetector,
    InjectionDetector,
    detect,
    detect_batch,
    analyze_rules,
    main,
)

# Backwards-compatible alias used in older tests
DetectionReport = DetectionResult

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "Label",
    "Rule",
    "DetectionResult",
    "DetectionReport",
    "LLMInjectionDetector",
    "InjectionDetector",
    "detect",
    "detect_batch",
    "analyze_rules",
    "main",
]
