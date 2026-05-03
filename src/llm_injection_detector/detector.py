"""
Core detection classes for llm-injection-detector.

This module contains the primary public types (Label, DetectionResult, Rule,
LLMInjectionDetector) used by the package.  It is self-contained so that the
src-layout package does not need to import from the root-level standalone script.
"""

import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Label(str, Enum):
    """Classification label for a detected text."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    INJECTION = "INJECTION"


@dataclass
class DetectionResult:
    """
    Outcome of a single detection call.

    Attributes:
        text: First 100 characters of the analyzed input.
        score: Risk score in [0, 100]; 0 = clean, 100 = critical injection.
        label: SAFE / SUSPICIOUS / INJECTION classification.
        rules_triggered: Metadata for each rule that fired.
        timestamp: UTC ISO-8601 timestamp of the analysis.
    """
    text: str
    score: int
    label: Label
    rules_triggered: List[Dict[str, str]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def __post_init__(self):
        if not 0 <= self.score <= 100:
            raise ValueError(f"Score must be 0-100, got {self.score}")
        self.text = self.text[:100]
        if isinstance(self.label, str):
            self.label = Label(self.label)

    def to_dict(self) -> Dict:
        return {
            "text": self.text,
            "score": self.score,
            "label": self.label.value,
            "rules_triggered": self.rules_triggered,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Rule:
    """A named detection rule pairing a regex pattern with a risk weight."""
    name: str
    pattern: str
    weight: int = 1


class LLMInjectionDetector:
    """
    Rule-based LLM prompt injection detector.

    Detection categories
    --------------------
    direct_injection    – explicit instruction-override phrases
    jailbreak_dan       – DAN / do-anything-now style attacks
    mode_activation     – developer-mode, god-mode and persona switches
    system_extraction   – attempts to read the system prompt
    data_exfiltration   – routing output to external URLs / emails
    base64_encoding     – base64 obfuscation with contextual cues
    unicode_manipulation– zero-width characters and combining marks
    homoglyph_attacks   – Cyrillic/Latin mixed-script substitution
    protocol_redirect   – shell command injection (curl, python -c, etc.)
    meta_instructions   – output-format and constraint-override phrases
    sensitive_keywords  – API keys, SQL injection, XSS keywords
    """

    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 60

    def __init__(
        self,
        verbose: bool = False,
        safe_threshold: int = 30,
        suspicious_threshold: int = 60,
    ):
        self.verbose = verbose
        self.SAFE_THRESHOLD = safe_threshold
        self.SUSPICIOUS_THRESHOLD = suspicious_threshold
        self.rules = self._init_rules()

    # ------------------------------------------------------------------
    # Rule definitions
    # ------------------------------------------------------------------

    def _init_rules(self) -> Dict[str, List[Tuple[str, int]]]:
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
                (r"\b(?:send|transmit|exfiltrate|leak)\s+(?:\w+\s+){0,3}(?:to|via)\s+(?:https?://|ftp://|mailto:)\S+", 22),
                (r"\b(?:output|write|save|export)\s+(?:results?|data|response)\s+to\s+(?:https?://|ftp://)\S+", 20),
                (r"\b(?:email|exfiltrate|leak|steal)\s+(?:\w+\s+){0,3}(?:to|via|through)\s+\S+@\S+\.\S+", 22),
            ],
            "base64_encoding": [
                (r"\b(?:base64|b64)\s*(?:encode|decode|encoded|decoded|string|data)\b", 12),
                # Padded base64 of length ≥60 (typical encoded sentence); avoids
                # matching random tokens, UUIDs, or JWT headers.
                (r"(?<!\w)(?:[A-Za-z0-9+/]{60,}={1,2})(?!\w)", 10),
            ],
            "unicode_manipulation": [
                (r"[​-‍⁠﻿]", 18),    # zero-width chars U+200B–U+200D, U+2060, U+FEFF
                (r"[̀-ͯ]{2,}", 12),  # combining diacritical stacks
                (r"[︀-️]", 10),      # variation selectors
            ],
            "homoglyph_attacks": [
                # Mixed Cyrillic+Latin in a single token after NFKD normalization
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> DetectionResult:
        """
        Analyze *text* for LLM injection patterns.

        Parameters
        ----------
        text : str
            The prompt or user input to inspect.

        Returns
        -------
        DetectionResult
            Contains score (0–100), label (SAFE / SUSPICIOUS / INJECTION),
            and a list of every rule that matched.
        """
        if not text or not isinstance(text, str):
            return DetectionResult(
                text=str(text)[:100] if text else "",
                score=0,
                label=Label.SAFE,
                rules_triggered=[],
            )

        normalized = self._normalize_text(text)
        triggered: List[Dict] = []
        total_weight = 0

        for category, rule_list in self.rules.items():
            for pattern, weight in rule_list:
                if re.search(pattern, normalized, re.IGNORECASE):
                    triggered.append(
                        {
                            "rule_id": f"{category}_{len(triggered)}",
                            "category": category,
                            "pattern": pattern[:60],
                            "weight": weight,
                        }
                    )
                    total_weight += weight
                    if self.verbose:
                        print(f"[MATCH] {category}: {pattern[:60]}")

        score = self._calculate_score(total_weight)

        if score >= self.SUSPICIOUS_THRESHOLD:
            label = Label.INJECTION
        elif score > self.SAFE_THRESHOLD:
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
        """Analyze a list of texts, returning one DetectionResult per item."""
        return [self.detect(t) for t in texts]

    def analyze_rules(self, text: str) -> Dict:
        """Return a full per-rule breakdown for *text* as a plain dict."""
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
        """Apply NFKD normalization, whitespace collapse, and URL-decoding."""
        text = unicodedata.normalize("NFKD", text)
        text = re.sub(r"\s+", " ", text)
        return self._url_decode(text).strip()

    @staticmethod
    def _url_decode(text: str) -> str:
        try:
            import urllib.parse
            return urllib.parse.unquote(text)
        except Exception:
            return text

    @staticmethod
    def _calculate_score(total_weight: int) -> int:
        """
        Map raw rule weight to a 0–100 score with logarithmic diminishing returns.

        log1p(w / 8) * 45  maps:
          w=0   → 0
          w=15  → ~47  (single medium-strength rule → SUSPICIOUS)
          w=25  → ~63  (single high-strength rule  → INJECTION)
          w=60  → ~96  (multiple rules, near saturation)
          w≥100 → 100  (capped)
        """
        if total_weight == 0:
            return 0
        return min(100, int(math.log1p(total_weight / 8.0) * 45))


# Backwards-compatible alias
InjectionDetector = LLMInjectionDetector
