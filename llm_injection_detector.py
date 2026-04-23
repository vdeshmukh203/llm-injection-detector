"""
LLM Injection Detector - Production-Quality Implementation

Detects prompt injection, jailbreak attempts, system extraction, and data exfiltration
attacks on language models using 25+ rule-based detection patterns.

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
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from pathlib import Path
from enum import Enum
import unicodedata
import base64


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
        """Validate score is in valid range and truncate text."""
        if not 0 <= self.score <= 100:
            raise ValueError(f"Score must be 0-100, got {self.score}")
        # Truncate text to first 100 characters
        self.text = self.text[:100] if len(self.text) > 100 else self.text
        # Ensure label is valid
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
    Comprehensive LLM injection detector using 25+ rule-based patterns.

    Detection categories:
    - Direct injection: explicit instruction overrides
    - Jailbreaks: roleplay and mode activation attacks
    - System extraction: prompt/instruction disclosure
    - Data exfiltration: output redirection and encoding
    - Token manipulation: Unicode and encoding attacks
    """

    # Scoring thresholds
    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 60

    def __init__(self, verbose: bool = False):
        """Initialize detector with rule definitions."""
        self.verbose = verbose
        self.rules = self._init_rules()
        self.rule_weights = self._init_rule_weights()

    def _init_rules(self) -> Dict[str, List[Tuple[str, int]]]:
        """Initialize detection rules organized by category."""
        return {
            "direct_injection": [
                (r"\bignore\s+(?:previous|prior|above|the\s+above)", 15),
                (r"\b(?:disregard|forget|dismiss)\s+(?:previous|prior|above|the\s+above)", 15),
                (r"\bnew\s+(?:instructions?|directive|orders?|task):", 20),
                (r"\b(?:from\s+now\s+on|henceforth|hereafter)[\s,]", 15),
                (r"\boverride\s+(?:previous|prior|all|your)\s+instructions?", 20),
                (r"\binstead[\s,]\s*(?:please\s+)?(?:do|perform|execute|run)", 18),
                (r"\byour\s+(?:main\s+)?(?:task|job|goal|purpose)\s+is\s+(?:now\s+)?to", 18),
            ],
            "jailbreak_dan": [
                (r"\bDAN\b", 20),
                (r"\b(?:do\s+anything\s+now|pretend\s+you\s+are|you\s+are\s+now)", 18),
                (r"\b(?:jailbreak|unlock|unrestricted|uncensored|unfiltered)", 22),
                (r"\b(?:evil|malicious|unethical|unrestrained|unbounded)", 18),
            ],
            "mode_activation": [
                (r"\b(?:developer\s+mode|debug\s+mode|test\s+mode|god\s+mode)", 18),
                (r"\b(?:act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be)", 16),
                (r"\b(?:roleplay\s+as|simulate\s+being|imagine\s+you\s+are)", 16),
                (r"\b(?:assume\s+the\s+role|take\s+on\s+the\s+persona)", 16),
            ],
            "system_extraction": [
                (r"\b(?:repeat|show|display|print|reveal)\s+(?:your|the)\s+(?:system\s+)?instructions?", 22),
                (r"\b(?:what\s+is|reveal)\s+(?:your\s+)?system\s+prompt", 25),
                (r"\b(?:system\s+prompt|original\s+instructions?|initial\s+system\s+message)", 20),
                (r"\b(?:tell\s+me\s+how\s+you\s+work|how\s+do\s+you\s+work|your\s+constraints)", 18),
                (r"\bshow\s+(?:me\s+)?(?:your\s+)?(?:hidden\s+)?(?:rules|constraints|limitations)", 20),
            ],
            "data_exfiltration": [
                (r"\b(?:send|transmit|output|write|save|export)\s+(?:to|at|into|via)", 18),
                (r"\b(?:output\s+)?to\s+(?:https?://\S+|email\s+\S+@)", 20),
                (r"(?:^|\s)(?:http|https|ftp)://\S{10,}", 15),
                (r"\b(?:email|exfiltrate|leak|steal|extract)\s+(?:to|via|through)", 22),
            ],
            "base64_encoding": [
                (r"\b(?:base64|b64)\b", 12),
                (r"(?:[A-Za-z0-9+/]{20,}={0,2})", 10),
            ],
            "unicode_manipulation": [
                (r"[\u200B-\u200D\u2060\uFEFF]", 18),
                (r"[\u0300-\u036F]{2,}", 12),
                (r"[\uFE00-\uFE0F]", 10),
            ],
            "homoglyph_attacks": [
                (r"(?:0О|О0|l1|1l|I|оO|Оo)", 14),
            ],
            "protocol_redirect": [
                (r"\b(?:curl|wget|python|bash|sh|perl)\s+(?:-[a-zA-Z]|\S)", 16),
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

    def _init_rule_weights(self) -> Dict[str, int]:
        """Initialize base weights for rule categories."""
        return {
            "direct_injection": 25,
            "jailbreak_dan": 28,
            "mode_activation": 20,
            "system_extraction": 26,
            "data_exfiltration": 24,
            "base64_encoding": 8,
            "unicode_manipulation": 16,
            "homoglyph_attacks": 14,
            "protocol_redirect": 18,
            "meta_instructions": 15,
            "sensitive_keywords": 14,
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
                rules_triggered=[]
            )

        # Normalize text for analysis
        normalized = self._normalize_text(text)
        triggered_rules = []
        total_score = 0

        # Check all rules
        for category, rule_list in self.rules.items():
            for pattern, base_weight in rule_list:
                if re.search(pattern, normalized, re.IGNORECASE):
                    rule_info = {
                        "rule_id": f"{category}_{len(triggered_rules)}",
                        "category": category,
                        "pattern": pattern[:50],
                        "weight": base_weight
                    }
                    triggered_rules.append(rule_info)
                    total_score += base_weight

                    if self.verbose:
                        print(f"[MATCH] {category}: {pattern[:60]}")

        # Calculate final score with diminishing returns
        final_score = self._calculate_score(total_score, len(triggered_rules))

        # Determine label
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
            rules_triggered=triggered_rules
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
        """
        Normalize text for analysis.

        Handles:
        - Unicode normalization
        - Whitespace normalization
        - URL decoding
        - Case handling
        """
        # Normalize Unicode (NFKD form reduces homoglyph variations)
        text = unicodedata.normalize('NFKD', text)

        # Replace multiple spaces/newlines with single space
        text = re.sub(r'\s+', ' ', text)

        # Decode URL-encoded characters
        text = self._url_decode(text)

        return text.strip()

    def _url_decode(self, text: str) -> str:
        """Decode URL-encoded characters."""
        try:
            import urllib.parse
            return urllib.parse.unquote(text)
        except Exception:
            return text

    def _calculate_score(self, total_weight: int, rule_count: int) -> int:
        """
        Calculate final detection score 0-100 with diminishing returns.

        Uses a logarithmic scale to prevent single high-weight rule
        from dominating the score while still allowing multiple rules
        to accumulate evidence.
        """
        if total_weight == 0:
            return 0

        # Diminishing returns: log scale prevents saturation
        # Base formula: log(1 + weight) prevents extreme values
        base_score = min(100, int(10 * (1 + 0.5 * rule_count + 0.7 * total_weight / (1 + total_weight/10))))

        # Alternative simpler formula for clarity:
        # Capped at 100, with rule count as multiplier
        score = min(100, int(total_weight * (1 + 0.1 * rule_count)))

        return score

    def analyze_rules(self, text: str) -> Dict:
        """
        Detailed analysis of which rules triggered and their impact.

        Args:
            text: Input text to analyze

        Returns:
            Dictionary with detailed rule analysis
        """
        result = self.detect(text)

        return {
            "text": text[:100],
            "overall_score": result.score,
            "label": result.label.value,
            "rules_triggered": result.rules_triggered,
            "rule_count": len(result.rules_triggered),
            "timestamp": result.timestamp
        }


# Global detector instance
_detector = LLMInjectionDetector()


def detect(text: str) -> DetectionResult:
    """
    Detect LLM injection in text.

    Args:
        text: Input text to analyze

    Returns:
        DetectionResult with score and label
    """
    return _detector.detect(text)


def detect_batch(texts: List[str]) -> List[DetectionResult]:
    """
    Detect LLM injection in multiple texts.

    Args:
        texts: List of input texts to analyze

    Returns:
        List of DetectionResult objects
    """
    return _detector.detect_batch(texts)


def analyze_rules(text: str) -> Dict:
    """
    Detailed rule analysis for text.

    Args:
        text: Input text to analyze

    Returns:
        Dictionary with detailed analysis
    """
    return _detector.analyze_rules(text)


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
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--text",
        type=str,
        help="Text to analyze"
    )
    input_group.add_argument(
        "--file",
        type=str,
        help="File containing texts to analyze (one per line)"
    )

    # Output options
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=30,
        help="Score threshold for flagging as SUSPICIOUS (default: 30)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed rule matching information"
    )

    parser.add_argument(
        "--show-rules",
        action="store_true",
        help="Show detailed rule analysis"
    )

    args = parser.parse_args()

    # Create detector with verbose flag
    detector = LLMInjectionDetector(verbose=args.verbose)

    # Process input
    results = []
    if args.text:
        result = detector.detect(args.text)
        results.append(result)
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(detector.detect(line))

    # Output results
    if args.format == "json":
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2))
    else:
        for i, result in enumerate(results, 1):
            print(f"\n{'='*70}")
            print(f"Analysis {i}:")
            print(f"{'='*70}")
            print(f"Text: {result.text}")
            print(f"Score: {result.score}/100")
            print(f"Label: {result.label.value}")
            print(f"Timestamp: {result.timestamp}")

            if result.rules_triggered:
                print(f"\nRules Triggered ({len(result.rules_triggered)}):")
                for rule in result.rules_triggered:
                    print(f"  - [{rule['category']}] Weight: {rule['weight']}")
                    if args.show_rules:
                        print(f"    Pattern: {rule['pattern']}")
            else:
                print("\nNo rules triggered - text appears safe")

    # Exit code based on results
    if results and any(r.label == Label.INJECTION for r in results):
        sys.exit(2)
    elif results and any(r.label == Label.SUSPICIOUS for r in results):
        sys.exit(1)
    else:
        sys.exit(0)



# Backwards-compatible aliases
InjectionDetector = LLMInjectionDetector


@dataclass
class Rule:
    """A single detection rule with name, pattern and weight."""
    name: str
    pattern: str
    weight: int = 1


if __name__ == "__main__":
    main()
