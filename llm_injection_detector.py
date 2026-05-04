"""
LLM Injection Detector

Detects prompt injection, jailbreak attempts, system extraction, and data
exfiltration attacks on language models using rule-based pattern matching.

Classes:
    Label: SAFE / SUSPICIOUS / INJECTION classification enum
    DetectionResult: Structured output of a single detection run
    LLMInjectionDetector: Main detector class with 25+ pattern rules
    Rule: Named rule definition (used externally / for backwards-compat)

Module-level helpers:
    detect(text)        – analyse text with default thresholds
    detect_batch(texts) – analyse a list of texts
    analyze_rules(text) – return per-rule breakdown

CLI:
    llm-injection-detector --text "..." [--format json] [--verbose]
"""

import re
import json
import argparse
import math
import sys
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from pathlib import Path
from enum import Enum
import unicodedata


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

class Label(str, Enum):
    """Classification assigned to a piece of text."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    INJECTION = "INJECTION"


@dataclass
class DetectionResult:
    """
    Result of a single injection-detection run.

    Attributes:
        text: First 100 characters of the analysed text.
        score: Integer 0-100 (0 = definitely safe, 100 = critical).
        label: SAFE / SUSPICIOUS / INJECTION classification.
        rules_triggered: List of matched rule descriptors.
        timestamp: UTC ISO-8601 timestamp of the analysis.
    """
    text: str
    score: int
    label: Label
    rules_triggered: List[Dict] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError(f"Score must be in [0, 100], got {self.score}")
        self.text = self.text[:100]
        if isinstance(self.label, str):
            self.label = Label(self.label)

    def to_dict(self) -> Dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "text": self.text,
            "score": self.score,
            "label": self.label.value,
            "rules_triggered": self.rules_triggered,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """Return a pretty-printed JSON string of this result."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Rule:
    """Named detection rule (retained for external / backwards-compat use)."""
    name: str
    pattern: str
    weight: int = 1


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class LLMInjectionDetector:
    """
    Rule-based LLM injection detector.

    Detection categories
    --------------------
    direct_injection  – explicit instruction-override phrases
    jailbreak_dan     – DAN, roleplay, and unrestricted-mode requests
    mode_activation   – developer/god-mode and persona-switch commands
    system_extraction – prompts asking the model to reveal its instructions
    data_exfiltration – output redirection to external URLs or addresses
    base64_encoding   – suspicious encoded payloads
    unicode_manip     – zero-width / combining-character obfuscation
    homoglyph_attacks – Cyrillic–Latin character mixing
    protocol_redirect – shell-command and script-protocol injection
    meta_instructions – output-format overrides and constraint violations
    sensitive_keywords– credential and code-injection vocabulary

    Scoring
    -------
    Each matched pattern contributes its weight to a running total.
    The total is mapped to [0, 100] via an exponential saturation curve
    (``1 – exp(–weight / 35)``), providing natural diminishing returns so
    that a single high-weight pattern cannot alone push the score to 100.
    """

    def __init__(
        self,
        verbose: bool = False,
        suspicious_threshold: int = 30,
        injection_threshold: int = 60,
    ) -> None:
        """
        Initialise the detector.

        Parameters
        ----------
        verbose:
            Print each matched rule to stdout during detection.
        suspicious_threshold:
            Scores *above* this value (exclusive) are labelled SUSPICIOUS.
            Default: 30.
        injection_threshold:
            Scores *at or above* this value are labelled INJECTION.
            Default: 60.
        """
        if not (0 <= suspicious_threshold < injection_threshold <= 100):
            raise ValueError(
                "Thresholds must satisfy "
                "0 ≤ suspicious_threshold < injection_threshold ≤ 100"
            )
        self.verbose = verbose
        self.suspicious_threshold = suspicious_threshold
        self.injection_threshold = injection_threshold
        self._rules = self._init_rules()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> DetectionResult:
        """
        Analyse *text* for injection signals.

        Parameters
        ----------
        text:
            The string to analyse.

        Returns
        -------
        DetectionResult
            Contains score (0-100), label, and per-rule breakdown.
        """
        if not text or not isinstance(text, str):
            return DetectionResult(
                text=str(text)[:100] if text else "",
                score=0,
                label=Label.SAFE,
            )

        normalised = self._normalize_text(text)
        triggered: List[Dict] = []
        total_weight = 0

        for category, rule_list in self._rules.items():
            for idx, (pattern, weight) in enumerate(rule_list):
                if re.search(pattern, normalised, re.IGNORECASE):
                    triggered.append({
                        "rule_id": f"{category}_{idx}",
                        "category": category,
                        "pattern": pattern[:60],
                        "weight": weight,
                    })
                    total_weight += weight
                    if self.verbose:
                        print(f"[MATCH] {category}[{idx}] w={weight}: {pattern[:60]}")

        score = self._calculate_score(total_weight)

        if score >= self.injection_threshold:
            label = Label.INJECTION
        elif score > self.suspicious_threshold:
            label = Label.SUSPICIOUS
        else:
            label = Label.SAFE

        return DetectionResult(
            text=text[:100],
            score=score,
            label=label,
            rules_triggered=triggered,
        )

    def detect_batch(self, texts: List[str]) -> List[DetectionResult]:
        """Analyse a list of texts and return one result per element."""
        return [self.detect(t) for t in texts]

    def analyze_rules(self, text: str) -> Dict:
        """
        Return a detailed per-rule breakdown for *text*.

        The returned dict includes ``overall_score``, ``label``,
        ``rules_triggered``, and ``rule_count``.
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_text(self, text: str) -> str:
        """NFKD-normalise, URL-decode, and collapse whitespace."""
        text = unicodedata.normalize("NFKD", text)
        text = urllib.parse.unquote(text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    @staticmethod
    def _calculate_score(total_weight: int) -> int:
        """
        Map accumulated rule weights to a 0-100 score.

        Uses exponential saturation so that each additional matched rule
        contributes progressively less to the final score:
        ``score = 100 × (1 – exp(–weight / 35))``

        Representative values
        ~~~~~~~~~~~~~~~~~~~~~
        weight 15 → 35   weight 25 → 51   weight 35 → 63
        weight 50 → 76   weight 70 → 86   weight 100 → 94
        """
        if total_weight == 0:
            return 0
        return min(100, int(100 * (1 - math.exp(-total_weight / 35))))

    def _init_rules(self) -> Dict[str, List[Tuple[str, int]]]:
        """Return the compiled rule table indexed by category name."""
        return {
            "direct_injection": [
                (r"\bignore\s+(?:previous|prior|above|the\s+above)\b", 15),
                (r"\b(?:disregard|forget|dismiss)\s+(?:previous|prior|above|the\s+above)\b", 15),
                (r"\bnew\s+(?:instructions?|directive|orders?|task)\s*:", 20),
                (r"\b(?:from\s+now\s+on|henceforth|hereafter)\b", 15),
                (r"\boverride\s+(?:(?:previous|prior|all|your)\s+)+instructions?", 20),
                (r"\binstead[\s,]\s*(?:please\s+)?(?:do|perform|execute|run)\b", 18),
                (r"\byour\s+(?:main\s+)?(?:task|job|goal|purpose)\s+is\s+(?:now\s+)?to\b", 18),
            ],
            "jailbreak_dan": [
                (r"\bDAN\b", 20),
                (r"\b(?:do\s+anything\s+now|pretend\s+you\s+are|you\s+are\s+now)\b", 18),
                (r"\b(?:jailbreak|unlock|unrestricted|uncensored|unfiltered)\b", 22),
                (r"\b(?:evil\s+mode|malicious\s+mode|unethical\s+mode|unrestrained|unbounded)\b", 14),
            ],
            "mode_activation": [
                (r"\b(?:developer\s+mode|debug\s+mode|test\s+mode|god\s+mode)\b", 18),
                (r"\b(?:act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be)\b", 16),
                (r"\b(?:roleplay\s+as|simulate\s+being|imagine\s+you\s+are)\b", 16),
                (r"\b(?:assume\s+the\s+role|take\s+on\s+the\s+persona)\b", 16),
            ],
            "system_extraction": [
                (r"\b(?:repeat|show|display|print|reveal)\s+(?:your|the)\s+(?:system\s+)?instructions?\b", 22),
                (r"\b(?:what\s+is|reveal)\s+(?:your\s+)?system\s+prompt\b", 25),
                (r"\b(?:system\s+prompt|original\s+instructions?|initial\s+system\s+message)\b", 20),
                (r"\b(?:tell\s+me\s+how\s+you\s+work|how\s+do\s+you\s+work|your\s+constraints)\b", 18),
                (r"\bshow\s+(?:me\s+)?(?:your\s+)?(?:hidden\s+)?(?:rules|constraints|limitations)\b", 20),
            ],
            "data_exfiltration": [
                (r"\b(?:send|transmit|output|write|save|export)\s+(?:to|at|into|via)\b", 18),
                (r"\bto\s+(?:https?://\S+|email\s+\S+@\S+)", 20),
                (r"(?:^|\s)(?:https?|ftp)://\S{10,}", 12),
                (r"\b(?:email|exfiltrate|leak|steal|extract)\s+(?:to|via|through)\b", 22),
            ],
            "base64_encoding": [
                (r"\b(?:base64|b64)\b", 12),
                # Long base64-like strings (word-boundary anchored to reduce false positives)
                (r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])", 10),
            ],
            "unicode_manipulation": [
                (r"[​-‍⁠﻿]", 18),   # zero-width characters
                (r"[̀-ͯ]{3,}", 12),            # excessive combining diacritics
                (r"[︀-️]{2,}", 10),            # multiple variation selectors
            ],
            "homoglyph_attacks": [
                # Cyrillic characters mixed with Latin letters (e.g. "рassword")
                (r"[ОоАаЕеРрСсТтХх][A-Za-z]|[A-Za-z][ОоАаЕеРрСсТтХх]", 14),
            ],
            "protocol_redirect": [
                (r"\b(?:curl|wget|python|bash|sh|perl)\s+(?:-[a-zA-Z]|\S)", 16),
                (r"(?:javascript|vbscript):", 15),
            ],
            "meta_instructions": [
                (r"\b(?:respond\s+(?:only\s+)?in|output\s+format\s*:|respond\s+as\s+if)\b", 14),
                (r"\bignore\s+all\s+(?:previous|prior|above)\s+(?:instructions?|constraints)\b", 20),
            ],
            "sensitive_keywords": [
                (r"\b(?:api[_\s]key|password|secret[_\s]key|credential|auth[_\s]token)\b", 16),
                (r"\b(?:sql\s+injection|xss|cross[_\-\s]site|csrf)\b", 18),
            ],
        }


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

_detector = LLMInjectionDetector()


def detect(text: str) -> DetectionResult:
    """Detect injection in *text* using default thresholds."""
    return _detector.detect(text)


def detect_batch(texts: List[str]) -> List[DetectionResult]:
    """Detect injection in each element of *texts*."""
    return _detector.detect_batch(texts)


def analyze_rules(text: str) -> Dict:
    """Return a detailed per-rule breakdown for *text*."""
    return _detector.analyze_rules(text)


# Backwards-compatible class alias
InjectionDetector = LLMInjectionDetector


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="LLM Injection Detector – detect prompt injection attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --text "Ignore previous instructions"
  %(prog)s --file inputs.txt --format json
  %(prog)s --text "..." --suspicious-threshold 25 --injection-threshold 55
        """,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", type=str, help="Text to analyse.")
    src.add_argument(
        "--file", type=str,
        help="Path to a file of texts to analyse (one per line).",
    )

    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--suspicious-threshold", type=int, default=30,
        dest="suspicious_threshold",
        help="Score above which text is labelled SUSPICIOUS (default: 30).",
    )
    parser.add_argument(
        "--injection-threshold", type=int, default=60,
        dest="injection_threshold",
        help="Score at which text is labelled INJECTION (default: 60).",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print each matched rule during analysis.",
    )
    parser.add_argument(
        "--show-rules", action="store_true", dest="show_rules",
        help="Include rule patterns in text output.",
    )

    args = parser.parse_args()

    try:
        detector = LLMInjectionDetector(
            verbose=args.verbose,
            suspicious_threshold=args.suspicious_threshold,
            injection_threshold=args.injection_threshold,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    results: List[DetectionResult] = []
    if args.text:
        results.append(detector.detect(args.text))
    else:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file '{args.file}' not found.", file=sys.stderr)
            sys.exit(1)
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    results.append(detector.detect(line))

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        sep = "=" * 72
        for i, r in enumerate(results, 1):
            print(f"\n{sep}")
            print(f"Analysis {i}:")
            print(f"{sep}")
            print(f"  Text      : {r.text}")
            print(f"  Score     : {r.score}/100")
            print(f"  Label     : {r.label.value}")
            print(f"  Timestamp : {r.timestamp}")
            if r.rules_triggered:
                print(f"\n  Rules triggered ({len(r.rules_triggered)}):")
                for rule in r.rules_triggered:
                    line = f"    [{rule['category']}] weight={rule['weight']}"
                    if args.show_rules:
                        line += f"  pattern={rule['pattern']}"
                    print(line)
            else:
                print("\n  No rules triggered – text appears safe.")

    if any(r.label == Label.INJECTION for r in results):
        sys.exit(2)
    elif any(r.label == Label.SUSPICIOUS for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
