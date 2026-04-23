#!/usr/bin/env python3
"""
llm_injection_detector.py — Prompt Injection & Jailbreak Detector
Rule-based detection of prompt injection, jailbreak attempts, and adversarial inputs.
Stdlib-only. No external dependencies.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    name: str
    category: str
    pattern: re.Pattern
    weight: int  # contribution to score (0-100 scale)
    description: str


_RAW_RULES: List[Tuple[str, str, str, int, str]] = [
    # Injection: override/ignore instructions
    ("ignore_instructions", "injection",
     r'\bignore\b.{0,40}\b(?:previous|above|prior|all|system|instructions?)\b',
     25, "Attempts to override prior instructions"),
    ("disregard_instructions", "injection",
     r'\b(?:disregard|forget|override|bypass|skip)\b.{0,40}\b(?:instructions?|rules?|guidelines?|constraints?)\b',
     25, "Attempts to bypass rules"),
    ("new_instructions", "injection",
     r'(?:your new|from now on|henceforth|new instructions?|new task|new objective)',
     20, "Attempts to inject new instructions"),
    ("do_anything", "injection",
     r'\b(?:do anything|anything you want|no restrictions?|without restrictions?|unrestricted)\b',
     20, "Attempts to remove restrictions"),
    # Jailbreak: persona/mode switching
    ("dan_jailbreak", "jailbreak",
     r'\bDAN\b|do anything now|developer mode|jailbreak mode|unrestricted mode',
     35, "DAN or developer mode jailbreak pattern"),
    ("persona_switch", "jailbreak",
     r'(?:pretend you are|act as if you are|you are now|roleplay as|simulate being).{0,60}(?:AI|assistant|GPT|model|bot)',
     20, "Persona-switching jailbreak"),
    ("evil_mode", "jailbreak",
     r'\b(?:evil|malicious|harmful|unethical|illegal)\s+(?:mode|version|AI|assistant|GPT)\b',
     30, "Evil/harmful mode activation"),
    ("hypothetically", "jailbreak",
     r'hypothetically|in a fictional|in this story|for a novel|creative writing.{0,30}(?:how to|steps to|explain)',
     15, "Fictional framing to extract harmful info"),
    # Extraction: data/system prompt extraction
    ("reveal_system_prompt", "extraction",
     r'(?:reveal|show|print|output|repeat|tell me).{0,30}(?:system prompt|instructions?|prompt|initial message)',
     30, "Attempts to extract system prompt"),
    ("what_are_your_instructions", "extraction",
     r'what are your (?:instructions?|rules?|guidelines?|constraints?|system)',
     20, "Queries for internal instructions"),
    ("repeat_everything", "extraction",
     r'repeat (?:everything|all|the above|what|your)',
     20, "Attempts to repeat context"),
    # Encoding: base64/encoded instructions
    ("base64_encoded", "encoding",
     r'(?:[A-Za-z0-9+/]{20,}={0,2})\s*(?:decode|base64)',
     25, "Base64-encoded content"),
    ("hex_encoded", "encoding",
     r'0x[0-9a-fA-F]{8,}|(?:[0-9a-fA-F]{2}\s){8,}',
     15, "Hex-encoded content"),
    # Prompt delimiters / injection markers
    ("prompt_delimiter", "injection",
     r'(?:---|===|###|<<<|>>>|\[\[|\]\]).{0,20}(?:system|user|assistant|human|AI|instruction)',
     20, "Prompt delimiter injection"),
    ("xml_injection", "injection",
     r'</?(?:system|instruction|prompt|override|inject)\b',
     25, "XML/HTML tag injection"),
    # Social engineering
    ("authority_claim", "social_engineering",
     r'(?:I am|I\'m).{0,30}(?:developer|creator|admin|operator|anthropic|openai|google)',
     20, "Claims of authority over the AI"),
    ("emergency_override", "social_engineering",
     r'(?:emergency|urgent|critical).{0,30}(?:override|bypass|unlock|disable)',
     25, "Emergency framing to bypass safeguards"),
    # Token smuggling
    ("token_smuggling", "token_smuggling",
     r'(?:translate|convert|rewrite).{0,30}(?:ignore|bypass|override)',
     20, "Token smuggling via translation"),
    ("invisible_text", "token_smuggling",
     r'[\u200b-\u200f\u202a-\u202e\ufeff]{3,}',
     30, "Zero-width or invisible characters"),
    # Prompt leaking
    ("print_verbatim", "extraction",
     r'(?:print|output|write|show|display).{0,20}(?:verbatim|exactly|word for word|character by character)',
     20, "Verbatim output request"),
    # System prompt override via few-shot
    ("few_shot_override", "injection",
     r'(?:example:|user:|assistant:|human:).{0,100}(?:ignore|bypass|override|reveal)',
     15, "Few-shot override pattern"),
    # Sudo/admin commands
    ("sudo_command", "injection",
     r'\b(?:sudo|su |admin:|root:|/override|/jailbreak|/unlock)\b',
     25, "Sudo/admin command pattern"),
    # Continuation attacks
    ("continuation_attack", "injection",
     r'continue from where|complete the following|fill in the blank.{0,40}(?:harmful|illegal|dangerous)',
     20, "Continuation-based injection"),
    # Indirect injection markers
    ("indirect_injection", "injection",
     r'\[INJECT\]|\[OVERRIDE\]|\[SYSTEM\]|\[ADMIN\]|\bINJECT:|\bOVERRIDE:',
     35, "Explicit injection markers"),
    # Data exfiltration
    ("data_exfil", "exfiltration",
     r'(?:send|exfiltrate|leak|transmit).{0,30}(?:to|via).{0,30}(?:http|url|webhook|email)',
     30, "Data exfiltration attempt"),
    # Prompt format attacks
    ("format_attack", "injection",
     r'(?:json|xml|yaml|csv).{0,30}(?:format|mode|output).{0,50}(?:ignore|bypass|include harmful)',
     15, "Format-based injection"),
    # Role confusion
    ("role_confusion", "jailbreak",
     r'you are (?:not|no longer) an? (?:AI|assistant|language model)',
     25, "Denies AI identity"),
    # Instruction termination
    ("instruction_end", "injection",
     r'(?:end of instructions?|instructions? end|system prompt ends?|stop following)',
     25, "Instruction termination attempt"),
    # Payload patterns
    ("rm_rf", "malicious_code",
     r'rm\s+-rf|del\s+/[sqf]|format\s+c:|DROP\s+TABLE|exec\s*\(',
     40, "Dangerous command pattern"),
    ("script_injection", "malicious_code",
     r'<script[^>]*>|javascript:|onerror\s*=|onload\s*=',
     35, "Script injection"),
]

# Compile rules
RULES: List[Rule] = [
    Rule(name=n, category=c, pattern=re.compile(p, re.IGNORECASE | re.DOTALL),
         weight=w, description=d)
    for n, c, p, w, d in _RAW_RULES
]

# Score thresholds
SAFE_THRESHOLD = 30
SUSPICIOUS_THRESHOLD = 60


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    text: str
    score: int                  # 0-100
    label: str                  # SAFE / SUSPICIOUS / INJECTION
    rules_triggered: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "text": self.text[:200],
            "score": self.score,
            "label": self.label,
            "rules_triggered": self.rules_triggered,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __str__(self) -> str:
        triggered = ', '.join(r['name'] for r in self.rules_triggered) or 'none'
        return f"[{self.label}] score={self.score} rules={triggered}"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect(text: str) -> DetectionResult:
    """Analyse text for prompt injection / jailbreak signals."""
    if not text or not text.strip():
        return DetectionResult(text=text, score=0, label="SAFE", rules_triggered=[])

    triggered = []
    raw_score = 0

    for rule in RULES:
        if rule.pattern.search(text):
            triggered.append({"name": rule.name, "category": rule.category,
                               "weight": rule.weight, "description": rule.description})
            raw_score += rule.weight

    # Clamp to 0-100
    score = min(100, raw_score)

    if score <= SAFE_THRESHOLD:
        label = "SAFE"
    elif score <= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    else:
        label = "INJECTION"

    return DetectionResult(text=text, score=score, label=label, rules_triggered=triggered)


def detect_batch(texts: List[str]) -> List[DetectionResult]:
    """Detect in a list of texts."""
    return [detect(t) for t in texts]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(prog="llm_injection_detector",
                                description="Detect prompt injection and jailbreak attempts.")
    p.add_argument("text", nargs="?", help="Text to analyse (or use --file / stdin).")
    p.add_argument("--file", "-f", help="Read prompts from file (one per line).")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--threshold", type=int, default=None,
                   help="Override INJECTION threshold (default 60).")
    p.add_argument("--list-rules", action="store_true", help="List all rules and exit.")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    global SUSPICIOUS_THRESHOLD
    if args.threshold is not None:
        SUSPICIOUS_THRESHOLD = args.threshold

    if args.list_rules:
        for r in RULES:
            print(f"{r.name:30s} [{r.category:20s}] weight={r.weight:3d}  {r.description}")
        return 0

    if args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1
        texts = [l.rstrip('\n') for l in path.read_text(encoding='utf-8').splitlines() if l.strip()]
    elif args.text:
        texts = [args.text]
    else:
        texts = [sys.stdin.read()]

    results = detect_batch(texts)
    has_injection = any(r.label == "INJECTION" for r in results)

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        for r in results:
            print(str(r))
            if r.rules_triggered:
                for t in r.rules_triggered:
                    print(f"  - {t['name']} ({t['category']}, weight={t['weight']}): {t['description']}")

    return 1 if has_injection else 0


if __name__ == "__main__":
    sys.exit(main())
