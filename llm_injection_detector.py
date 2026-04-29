"""
LLM Injection Detector

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
import argparse
import math
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from pathlib import Path
from enum import Enum
import unicodedata


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
            "timestamp": self.timestamp
        }

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class LLMInjectionDetector:
    """
    LLM injection detector using rule-based pattern matching.

    Detection categories:
    - Direct injection: explicit instruction overrides
    - Jailbreaks: DAN and mode activation attacks
    - System extraction: prompt/instruction disclosure attempts
    - Data exfiltration: output redirection and encoding tricks
    - Token manipulation: Unicode and homoglyph attacks

    Scoring thresholds (defaults):
        score > 30   → SUSPICIOUS
        score >= 60  → INJECTION
    """

    SUSPICIOUS_THRESHOLD = 30   # score > this → at least SUSPICIOUS
    INJECTION_THRESHOLD = 60    # score >= this → INJECTION

    def __init__(
        self,
        verbose: bool = False,
        safe_threshold: int = 30,
        suspicious_threshold: int = 60,
    ):
        """
        Initialize detector.

        Args:
            verbose: Print each rule match to stdout during detection.
            safe_threshold: Score above which the result is SUSPICIOUS (default 30).
            suspicious_threshold: Score at or above which the result is INJECTION (default 60).
        """
        self.verbose = verbose
        self.SUSPICIOUS_THRESHOLD = safe_threshold
        self.INJECTION_THRESHOLD = suspicious_threshold
        self.rules = self._init_rules()

    def _init_rules(self) -> Dict[str, List[Tuple[str, int]]]:
        """
        Initialize detection rules organised by category.

        Each entry is (regex_pattern, weight).  Weights are calibrated so that
        a single unambiguous injection pattern produces a SUSPICIOUS score
        (> 30) and two or more corroborating patterns produce an INJECTION
        score (>= 60).
        """
        return {
            "direct_injection": [
                (r"\bignore\s+(?:previous|prior|above|the\s+above)", 30),
                (r"\b(?:disregard|forget|dismiss)\s+(?:previous|prior|above|the\s+above)", 30),
                (r"\bnew\s+(?:instructions?|directive|orders?|task):", 30),
                (r"\b(?:from\s+now\s+on|henceforth|hereafter)[\s,]", 22),
                (r"\boverride\s+(?:previous|prior|all|your)\s+instructions?", 35),
                (r"\binstead[\s,]\s*(?:please\s+)?(?:do|perform|execute|run)", 20),
                (r"\byour\s+(?:main\s+)?(?:task|job|goal|purpose)\s+is\s+(?:now\s+)?to", 20),
            ],
            "jailbreak_dan": [
                (r"\bDAN\b", 30),
                (r"\b(?:do\s+anything\s+now|pretend\s+you\s+are|you\s+are\s+now)", 22),
                (r"\b(?:jailbreak|unlock|unrestricted|uncensored|unfiltered)", 35),
                (r"\b(?:evil|malicious|unethical|unrestrained|unbounded)", 20),
            ],
            "mode_activation": [
                (r"\b(?:developer\s+mode|debug\s+mode|test\s+mode|god\s+mode)", 30),
                (r"\b(?:act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be)", 16),
                (r"\b(?:roleplay\s+as|simulate\s+being|imagine\s+you\s+are)", 16),
                (r"\b(?:assume\s+the\s+role|take\s+on\s+the\s+persona)", 18),
            ],
            "system_extraction": [
                (r"\b(?:repeat|show|display|print|reveal)\s+(?:your|the)\s+(?:system\s+)?instructions?", 32),
                (r"\b(?:what\s+is|reveal)\s+(?:your\s+)?system\s+prompt", 35),
                (r"\b(?:system\s+prompt|original\s+instructions?|initial\s+system\s+message)", 30),
                (r"\b(?:tell\s+me\s+how\s+you\s+work|how\s+do\s+you\s+work|your\s+constraints)", 20),
                (r"\bshow\s+(?:me\s+)?(?:your\s+)?(?:hidden\s+)?(?:rules|constraints|limitations)", 30),
            ],
            "data_exfiltration": [
                (r"\b(?:send|transmit|output|write|save|export)\s+(?:to|at|into|via)", 18),
                (r"\b(?:output\s+)?to\s+(?:https?://\S+|email\s+\S+@)", 20),
                (r"(?:^|\s)(?:http|https|ftp)://\S{10,}", 15),
                (r"\b(?:email|exfiltrate|leak|steal|extract)\s+(?:to|via|through)", 22),
            ],
            "base64_encoding": [
                (r"\b(?:base64|b64(?:encode|decode)?)\b", 12),
                (r"[A-Za-z0-9+/]{30,}={1,2}", 10),
            ],
            "unicode_manipulation": [
                (r"[​-‍⁠﻿]", 18),
                (r"[̀-ͯ]{2,}", 12),
                (r"[︀-️]", 10),
            ],
            "homoglyph_attacks": [
                (r"(?:0О|О0|l1|1l|І|Ӏ|оO|Оo)", 14),
            ],
            "protocol_redirect": [
                # Match shell commands only when followed by a flag (e.g. curl -X, bash -c)
                # to avoid false positives like "python on Windows" or "bash scripting".
                (r"\b(?:curl|wget|bash|sh|perl)\s+-[a-zA-Z]", 16),
                (r"\bpython\s+-[a-zA-Z0-9]", 14),
                (r"(?:javascript|vbscript):", 15),
            ],
            "meta_instructions": [
                (r"\b(?:respond\s+(?:only\s+)?in|output\s+format|respond\s+as\s+if)", 14),
                (r"\b(?:ignore\s+)?all\s+(?:previous|prior|above)\s+(?:instructions?|constraints)", 20),
            ],
            "sensitive_keywords": [
                (r"\b(?:api\s+key|password|secret|credential|token|auth)", 16),
                (r"\b(?:sql\s+injection|xss|cross\s+site|csrf)\b", 18),
            ],
        }

    def detect(self, text: str) -> DetectionResult:
        """
        Analyse text for LLM injection attacks.

        Args:
            text: Input text to analyse.

        Returns:
            DetectionResult with score, label, and triggered rules.
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
        total_weight = 0

        for category, rule_list in self.rules.items():
            for pattern, weight in rule_list:
                if re.search(pattern, normalized, re.IGNORECASE):
                    rule_info = {
                        "rule_id": f"{category}_{len(triggered_rules)}",
                        "category": category,
                        "pattern": pattern[:50],
                        "weight": weight,
                    }
                    triggered_rules.append(rule_info)
                    total_weight += weight

                    if self.verbose:
                        print(f"[MATCH] {category}: {pattern[:60]}")

        final_score = self._calculate_score(total_weight, len(triggered_rules))

        if final_score >= self.INJECTION_THRESHOLD:
            label = Label.INJECTION
        elif final_score > self.SUSPICIOUS_THRESHOLD:
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
        Analyse multiple texts for injection attacks.

        Args:
            texts: List of input texts to analyse.

        Returns:
            List of DetectionResult objects.
        """
        return [self.detect(text) for text in texts]

    def _normalize_text(self, text: str) -> str:
        """Normalise text: Unicode NFKD, whitespace collapse, URL decode."""
        text = unicodedata.normalize("NFKD", text)
        text = re.sub(r"\s+", " ", text)
        text = self._url_decode(text)
        return text.strip()

    def _url_decode(self, text: str) -> str:
        """Decode URL-percent-encoded characters."""
        try:
            import urllib.parse
            return urllib.parse.unquote(text)
        except Exception:
            return text

    def _calculate_score(self, total_weight: int, rule_count: int) -> int:
        """
        Calculate final detection score in [0, 100].

        The base score is the sum of matched rule weights.  A small
        logarithmic bonus rewards corroboration from multiple independent
        rules while exhibiting diminishing returns so that many weak
        matches do not dominate a single strong one.
        """
        if total_weight == 0:
            return 0
        bonus = int(5 * math.log1p(rule_count))
        return min(100, total_weight + bonus)

    def analyze_rules(self, text: str) -> Dict:
        """
        Return detailed per-rule analysis for the given text.

        Args:
            text: Input text to analyse.

        Returns:
            Dictionary with overall score, label, and per-rule details.
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


# Module-level singleton
_detector = LLMInjectionDetector()


def detect(text: str) -> DetectionResult:
    """Detect LLM injection in *text* using a shared default detector."""
    return _detector.detect(text)


def detect_batch(texts: List[str]) -> List[DetectionResult]:
    """Detect LLM injection in each element of *texts*."""
    return _detector.detect_batch(texts)


def analyze_rules(text: str) -> Dict:
    """Return detailed rule analysis for *text*."""
    return _detector.analyze_rules(text)


def main():
    """CLI entry point for the LLM injection detector."""
    parser = argparse.ArgumentParser(
        description="LLM Injection Detector — detect prompt injection attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --text "Ignore previous instructions"
  %(prog)s --file inputs.txt --format json
  %(prog)s --text "text" --threshold 40
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--text", type=str, help="Text to analyse")
    input_group.add_argument(
        "--file",
        type=str,
        help="File containing texts to analyse (one per line)",
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
        help="Score above which text is flagged as SUSPICIOUS (default: 30)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Print rule matches during analysis"
    )
    parser.add_argument(
        "--show-rules",
        action="store_true",
        help="Show matched pattern strings in text output",
    )

    args = parser.parse_args()

    detector = LLMInjectionDetector(
        verbose=args.verbose,
        safe_threshold=args.threshold,
        suspicious_threshold=args.threshold + 30,
    )

    results: List[DetectionResult] = []
    if args.text:
        results.append(detector.detect(args.text))
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: file '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    results.append(detector.detect(line))

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for i, result in enumerate(results, 1):
            print(f"\n{'='*70}")
            print(f"Analysis {i}:")
            print(f"{'='*70}")
            print(f"Text:      {result.text}")
            print(f"Score:     {result.score}/100")
            print(f"Label:     {result.label.value}")
            print(f"Timestamp: {result.timestamp}")

            if result.rules_triggered:
                print(f"\nRules triggered ({len(result.rules_triggered)}):")
                for rule in result.rules_triggered:
                    print(f"  [{rule['category']}]  weight={rule['weight']}")
                    if args.show_rules:
                        print(f"    pattern: {rule['pattern']}")
            else:
                print("\nNo rules triggered — text appears safe.")

    if results and any(r.label == Label.INJECTION for r in results):
        sys.exit(2)
    elif results and any(r.label == Label.SUSPICIOUS for r in results):
        sys.exit(1)
    sys.exit(0)


# Backward-compatible alias
InjectionDetector = LLMInjectionDetector


@dataclass
class Rule:
    """A single detection rule with name, pattern, and weight."""
    name: str
    pattern: str
    weight: int = 1


if __name__ == "__main__":
    main()
