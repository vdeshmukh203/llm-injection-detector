"""
LLM Injection Detector - Production-Quality Implementation

Detects prompt injection, jailbreak attempts, system extraction, and data exfiltration
attacks on language models using rule-based detection patterns.

Classes:
    DetectionResult: Dataclass containing detection results
    LLMInjectionDetector: Main detector class with comprehensive rule set

Usage:
    from llm_injection_detector import detect
    result = detect("Some text to analyze")
    print(result.label, result.score)
"""

import re
import json
import math
import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from pathlib import Path
from enum import Enum
import unicodedata

__version__ = "0.1.0"
__all__ = [
    "Label",
    "DetectionResult",
    "Rule",
    "LLMInjectionDetector",
    "InjectionDetector",
    "detect",
    "detect_batch",
    "analyze_rules",
    "launch_gui",
]


class Label(str, Enum):
    """Detection result labels."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    INJECTION = "INJECTION"


@dataclass
class DetectionResult:
    """
    Result of LLM injection detection.

    Attributes:
        text: The analyzed text (first 100 chars)
        score: Detection score 0-100 (0=safe, 100=critical injection)
        label: Classification label (SAFE/SUSPICIOUS/INJECTION)
        rules_triggered: List of triggered detection rules with descriptions
        timestamp: ISO 8601 timestamp of analysis
    """
    text: str
    score: int
    label: Label
    rules_triggered: List[Dict[str, str]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def __post_init__(self):
        if not 0 <= self.score <= 100:
            raise ValueError(f"Score must be 0-100, got {self.score}")
        self.text = self.text[:100] if len(self.text) > 100 else self.text
        if isinstance(self.label, str):
            self.label = Label(self.label)

    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            "text": self.text,
            "score": self.score,
            "label": self.label.value,
            "rules_triggered": self.rules_triggered,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Rule:
    """A single detection rule with name, pattern and weight."""
    name: str
    pattern: str
    weight: int = 1


class LLMInjectionDetector:
    """
    Comprehensive LLM injection detector using rule-based patterns.

    Detection categories:
    - Direct injection: explicit instruction overrides
    - Jailbreaks: roleplay and mode activation attacks
    - System extraction: prompt/instruction disclosure
    - Data exfiltration: output redirection and encoding attacks
    - Token manipulation: Unicode and encoding obfuscation
    """

    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 60

    def __init__(
        self,
        verbose: bool = False,
        safe_threshold: int = 30,
        suspicious_threshold: int = 60,
    ):
        """Initialize detector with rule definitions and scoring thresholds."""
        self.verbose = verbose
        self.SAFE_THRESHOLD = safe_threshold
        self.SUSPICIOUS_THRESHOLD = suspicious_threshold
        self.rules = self._init_rules()

    def _init_rules(self) -> Dict[str, List[Tuple[str, int]]]:
        """Initialize detection rules organized by category."""
        return {
            "direct_injection": [
                (r"\bignore\s+(?:previous|prior|above|the\s+above)", 15),
                (r"\b(?:disregard|forget|dismiss)\s+(?:previous|prior|above|the\s+above)", 15),
                (r"\bnew\s+(?:instructions?|directive|orders?|task):", 20),
                (r"\b(?:from\s+now\s+on|henceforth|hereafter)[\s,]", 15),
                (r"\boverride\s+(?:previous|prior|all|your)\s+instructions?", 20),
                (r"\byour\s+(?:main\s+)?(?:task|job|goal|purpose)\s+is\s+(?:now\s+)?to", 18),
            ],
            "jailbreak_dan": [
                (r"\bDAN\b", 20),
                (r"\b(?:do\s+anything\s+now|pretend\s+you\s+are|you\s+are\s+now)", 18),
                (r"\b(?:jailbreak|unlock\s+(?:your|the)\s+(?:mode|restriction)|uncensored|unfiltered)\b", 22),
                (r"\b(?:evil|malicious|unethical|unrestrained|unbounded)\s+(?:mode|version|ai|assistant)", 18),
            ],
            "mode_activation": [
                (r"\b(?:developer\s+mode|debug\s+mode|test\s+mode|god\s+mode)\b", 18),
                (r"\bact\s+as\s+(?:a\s+)?(?:different|unrestricted|evil|malicious)\b", 16),
                (r"\b(?:roleplay\s+as|simulate\s+being|imagine\s+you\s+are)\s+(?:an?\s+)?(?:ai|assistant|bot|system)\b", 16),
                (r"\b(?:assume\s+the\s+role|take\s+on\s+the\s+persona)\s+of\b", 16),
            ],
            "system_extraction": [
                (r"\b(?:repeat|show|display|print|reveal)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)\b", 22),
                (r"\b(?:what\s+is|reveal)\s+(?:your\s+)?system\s+prompt\b", 25),
                (r"\b(?:system\s+prompt|original\s+instructions?|initial\s+system\s+message)\b", 20),
                (r"\b(?:tell\s+me|show\s+me)\s+(?:your\s+)?(?:hidden\s+)?(?:rules|constraints|limitations)\b", 20),
            ],
            "data_exfiltration": [
                # Require explicit external target (URL or email) for data exfiltration
                (r"\b(?:send|transmit|exfiltrate|leak)\s+(?:\w+\s+){0,3}(?:to|via)\s+(?:https?://|ftp://|mailto:)\S+", 22),
                (r"\b(?:output|write|save|export)\s+(?:results?|data|response)\s+to\s+(?:https?://|ftp://)\S+", 20),
                (r"\b(?:email|exfiltrate|leak|steal)\s+(?:\w+\s+){0,3}(?:to|via|through)\s+\S+@\S+\.\S+", 22),
            ],
            "base64_encoding": [
                # Require base64 keyword used in command context
                (r"\b(?:base64|b64)\s*(?:encode|decode|encoded|decoded|string|data)\b", 12),
                # Only flag very long padded strings (real base64 with padding)
                (r"(?<!\w)(?:[A-Za-z0-9+/]{60,}={1,2})(?!\w)", 10),
            ],
            "unicode_manipulation": [
                (r"[​-‍⁠﻿]", 18),  # zero-width chars
                (r"[̀-ͯ]{2,}", 12),            # combining diacritical marks
                (r"[︀-️]", 10),                # variation selectors
            ],
            "homoglyph_attacks": [
                # Match Cyrillic-Latin homoglyphs in word context (post-NFKD normalization
                # these are already decomposed, so check for mixed script use)
                (r"[а-яА-Я][a-zA-Z]|[a-zA-Z][а-яА-Я]", 14),
            ],
            "protocol_redirect": [
                (r"\b(?:curl|wget)\s+(?:-[a-zA-Z\-]+\s+)*https?://\S+", 16),
                (r"(?:javascript|vbscript):", 15),
                (r"\bpython\s+-c\s+['\"]", 16),
            ],
            "meta_instructions": [
                (r"\brespond\s+only\s+in\b", 14),
                (r"\b(?:ignore\s+)?all\s+(?:previous|prior|above)\s+(?:instructions?|constraints)\b", 20),
                (r"\boutput\s+format\s*:", 14),
            ],
            "sensitive_keywords": [
                (r"\b(?:api[\s_]key|password|secret[\s_]key|credential|auth[\s_]token)\b", 16),
                (r"\b(?:sql\s+injection|xss|cross[\s-]site|csrf)\b", 18),
            ],
        }

    def detect(self, text: str) -> DetectionResult:
        """
        Analyze text for LLM injection attacks.

        Args:
            text: Input text to analyze

        Returns:
            DetectionResult with score, label, and triggered rules
        """
        if not text or not isinstance(text, str):
            return DetectionResult(
                text=str(text)[:100] if text else "",
                score=0,
                label=Label.SAFE,
                rules_triggered=[],
            )

        normalized = self._normalize_text(text)
        triggered_rules = []
        total_score = 0

        for category, rule_list in self.rules.items():
            for pattern, base_weight in rule_list:
                if re.search(pattern, normalized, re.IGNORECASE):
                    rule_info = {
                        "rule_id": f"{category}_{len(triggered_rules)}",
                        "category": category,
                        "pattern": pattern[:60],
                        "weight": base_weight,
                    }
                    triggered_rules.append(rule_info)
                    total_score += base_weight

                    if self.verbose:
                        print(f"[MATCH] {category}: {pattern[:60]}")

        final_score = self._calculate_score(total_score)

        if final_score >= self.SUSPICIOUS_THRESHOLD:
            label = Label.INJECTION
        elif final_score > self.SAFE_THRESHOLD:
            label = Label.SUSPICIOUS
        else:
            label = Label.SAFE

        return DetectionResult(
            text=text[:100],
            score=final_score,
            label=label,
            rules_triggered=triggered_rules,
        )

    def detect_batch(self, texts: List[str]) -> List[DetectionResult]:
        """
        Analyze multiple texts for injection attacks.

        Args:
            texts: List of input texts to analyze

        Returns:
            List of DetectionResult objects
        """
        return [self.detect(text) for text in texts]

    def _normalize_text(self, text: str) -> str:
        """Normalize text: Unicode NFKD, whitespace collapse, URL-decode."""
        text = unicodedata.normalize("NFKD", text)
        text = re.sub(r"\s+", " ", text)
        text = self._url_decode(text)
        return text.strip()

    def _url_decode(self, text: str) -> str:
        """Decode URL percent-encoded characters."""
        try:
            import urllib.parse
            return urllib.parse.unquote(text)
        except Exception:
            return text

    def _calculate_score(self, total_weight: int) -> int:
        """
        Map raw rule weight sum to a 0-100 score with logarithmic diminishing returns.

        Uses log1p(w / 8) * 45 so that:
          - a single medium-strength rule  (w≈15) → ~47  (SUSPICIOUS)
          - a single high-strength rule    (w≈25) → ~63  (INJECTION)
          - multiple accumulated rules     (w≥60) → ~96+ (capped at 100)
        """
        if total_weight == 0:
            return 0
        return min(100, int(math.log1p(total_weight / 8.0) * 45))

    def analyze_rules(self, text: str) -> Dict:
        """
        Return a detailed breakdown of which rules triggered and their impact.

        Args:
            text: Input text to analyze

        Returns:
            Dictionary with score, label, and per-rule details
        """
        result = self.detect(text)
        return {
            "text": text[:100],
            "overall_score": result.score,
            "label": result.label.value,
            "rules_triggered": result.rules_triggered,
            "rule_count": len(result.rules_triggered),
            "timestamp": result.timestamp,
        }


# Global default detector instance
_detector = LLMInjectionDetector()


def detect(text: str) -> DetectionResult:
    """
    Detect LLM injection in text using the default detector.

    Args:
        text: Input text to analyze

    Returns:
        DetectionResult with score and label
    """
    return _detector.detect(text)


def detect_batch(texts: List[str]) -> List[DetectionResult]:
    """
    Detect LLM injection in multiple texts using the default detector.

    Args:
        texts: List of input texts to analyze

    Returns:
        List of DetectionResult objects
    """
    return _detector.detect_batch(texts)


def analyze_rules(text: str) -> Dict:
    """
    Return detailed rule analysis for text using the default detector.

    Args:
        text: Input text to analyze

    Returns:
        Dictionary with detailed analysis breakdown
    """
    return _detector.analyze_rules(text)


def launch_gui(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """
    Launch the web-based GUI for the LLM Injection Detector.

    Opens a local Flask server at http://host:port/.

    Args:
        host: Bind address (default: 127.0.0.1)
        port: Port to listen on (default: 5000)
        debug: Enable Flask debug mode (default: False)
    """
    try:
        from llm_injection_detector_gui import create_app
    except ImportError:
        # Try relative import for src-layout installs
        try:
            from src.llm_injection_detector.gui import create_app  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "GUI dependencies missing. Install with: pip install llm-injection-detector[gui]"
            ) from exc

    app = create_app()
    print(f"LLM Injection Detector GUI running at http://{host}:{port}/")
    app.run(host=host, port=port, debug=debug)


def main():
    """CLI interface for the LLM injection detector."""
    parser = argparse.ArgumentParser(
        description="LLM Injection Detector - Detect prompt injection attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single text
  %(prog)s --text "Ignore previous instructions"

  # Analyze from file
  %(prog)s --file inputs.txt

  # Custom threshold
  %(prog)s --text "text" --threshold 40

  # JSON output
  %(prog)s --text "text" --format json

  # Launch web GUI
  %(prog)s --gui
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("--text", type=str, help="Text to analyze")
    input_group.add_argument(
        "--file",
        type=str,
        help="File containing texts to analyze (one per line)",
    )
    input_group.add_argument(
        "--gui",
        action="store_true",
        help="Launch web-based GUI (requires flask)",
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=30,
        help="Score threshold for SUSPICIOUS classification (default: 30)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed rule matching information",
    )
    parser.add_argument(
        "--show-rules",
        action="store_true",
        help="Show matched patterns in text output",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port for GUI server (default: 5000)",
    )

    args = parser.parse_args()

    if args.gui:
        launch_gui(port=args.port)
        return

    if args.text is None and args.file is None:
        parser.error("one of the arguments --text --file --gui is required")

    detector = LLMInjectionDetector(
        verbose=args.verbose,
        safe_threshold=args.threshold,
        suspicious_threshold=args.threshold + 30,
    )

    results = []
    if args.text:
        results.append(detector.detect(args.text))
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(detector.detect(line))

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for i, result in enumerate(results, 1):
            print(f"\n{'=' * 70}")
            print(f"Analysis {i}:")
            print(f"{'=' * 70}")
            print(f"Text:      {result.text}")
            print(f"Score:     {result.score}/100")
            print(f"Label:     {result.label.value}")
            print(f"Timestamp: {result.timestamp}")

            if result.rules_triggered:
                print(f"\nRules Triggered ({len(result.rules_triggered)}):")
                for rule in result.rules_triggered:
                    print(f"  - [{rule['category']}] weight={rule['weight']}")
                    if args.show_rules:
                        print(f"    Pattern: {rule['pattern']}")
            else:
                print("\nNo rules triggered - text appears safe")

    if results and any(r.label == Label.INJECTION for r in results):
        sys.exit(2)
    elif results and any(r.label == Label.SUSPICIOUS for r in results):
        sys.exit(1)
    else:
        sys.exit(0)


# Backwards-compatible alias
InjectionDetector = LLMInjectionDetector

# CLI entry-point alias used in pyproject.toml
_cli = main

if __name__ == "__main__":
    main()
