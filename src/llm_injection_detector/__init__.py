"""
llm_injection_detector: Static and heuristic prompt injection vulnerability detector.

This package re-exports the public API from the root-level module
``llm_injection_detector``.  Install with ``pip install llm-injection-detector``
and then::

    from llm_injection_detector import detect, LLMInjectionDetector

See the project README for full usage documentation.
"""

# The canonical implementation lives in the root-level module.
# This shim makes the src/ layout importable for IDEs and editable installs.
from llm_injection_detector import (  # noqa: F401
    __author__,
    __license__,
    __version__,
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

__all__ = [
    "__author__",
    "__license__",
    "__version__",
    "Label",
    "Rule",
    "DetectionResult",
    "LLMInjectionDetector",
    "InjectionDetector",
    "detect",
    "detect_batch",
    "analyze_rules",
    "main",
]
