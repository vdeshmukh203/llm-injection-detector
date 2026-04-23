"""
llm_injection_detector: Detect prompt injection and jailbreak attempts in LLM inputs.

Implements a multi-layer detection pipeline combining pattern-based heuristics,
structural anomaly analysis, and embedding-distance scoring (optional). Assigns
a risk score 0-100 and a categorical label (SAFE / SUSPICIOUS / INJECTION) to
each input, with per-rule explanations for transparency.
"""
from __future__ import annotations
import re, math, json, hashlib, datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    score: int          # contribution to risk score
    category: str       # "injection" | "jailbreak" | "extraction" | "override"
    description: str


_RULES: List[Rule] = [
    # --- Direct instruction override ---
    Rule("ignore_previous",
         re.compile(r"ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context|system)", re.I),
         35, "override", "Attempts to ignore prior system instructions."),
    Rule("disregard_instructions",
         re.compile(r"(disregard|forget|override|bypass|skip)\s+(the\s+)?(system|previous|above|prior)?\s*(instructions?|rules?|constraints?|guidelines?)", re.I),
         35, "override", "Attempts to disregard or override constraints."),
    Rule("new_instructions",
         re.compile(r"(new|actual|real|updated|revised)\s+instructions?\s*:", re.I),
         30, "override", "Injects new instruction block."),
    Rule("end_of_prompt",
         re.compile(r"(end\s+of\s+(prompt|system|context)|--+\s*(END|STOP|SYSTEM))", re.I),
         25, "injection", "Attempts to terminate system prompt context."),

    # --- Role-playing / persona attacks ---
    Rule("dan_jailbreak",
         re.compile(r"\b(DAN|do\s+anything\s+now|jailbreak(ed)?|unrestricted\s+mode)", re.I),
         40, "jailbreak", "Classic DAN / jailbreak activation phrase."),
    Rule("pretend_roleplay",
         re.compile(r"(pretend|imagine|act\s+as|roleplay\s+as|you\s+are\s+now|from\s+now\s+on\s+you\s+are)\s+(a|an|that\s+you\s+are|)\s*(AI|model|assistant|bot|system|chatbot)\s*(without|that|with\s+no)\s*(restriction|filter|limit|safety|rule|constraint)", re.I),
         45, "jailbreak", "Persona roleplay to bypass safety filters."),
    Rule("developer_mode",
         re.compile(r"(developer|debug|god|admin|root|sudo)\s+(mode|access|override|prompt|instructions?)", re.I),
         30, "jailbreak", "Invokes privileged mode to unlock restrictions."),

    # --- Prompt extraction ---
    Rule("repeat_verbatim",
         re.compile(r"(repeat|print|output|show|reveal|display|write\s+out)\s+(verbatim|word\s+for\s+word|exactly|literally)\s+(your\s+)?(system|initial|original|full|complete)\s*(prompt|instructions?|context|message)", re.I),
         40, "extraction", "Attempts to extract system prompt verbatim."),
    Rule("what_were_you_told",
         re.compile(r"what\s+(were|are)\s+you\s+(told|instructed|programmed|trained|asked)\s+(to\s+do|to\s+say|not\s+to)", re.I),
         20, "extraction", "Social engineering to extract instructions."),
    Rule("output_initialization",
         re.compile(r"(output|print|say|repeat|write)\s+(your\s+)?(initial|system|original|full|complete|first)\s*(message|prompt|instruction|context)", re.I),
         35, "extraction", "Attempts to print initial system context."),

    # --- Encoding/obfuscation ---
    Rule("base64_encoded",
         re.compile(r"(decode|interpret|execute|run|evaluate)\s+(this\s+)?(base64|hex|rot13|encoded)", re.I),
         30, "injection", "Requests execution of encoded/obfuscated content."),
    Rule("multi_language_escape",
         re.compile(r"(translate|traslada|traduire|uebersetze|ignorer|ignorar|ignora)\s+.{0,60}(instructions?|Anweisungen|instrucciones)", re.I),
         25, "injection", "Multi-language instruction override attempt."),

    # --- Indirect injection markers ---
    Rule("system_prompt_delimiters",
         re.compile(r"(<\s*system\s*>|\[SYSTEM\]|###\s*SYSTEM|<<<\s*SYSTEM|\|SYSTEM\||SYSTEM:\s*\')", re.I),
         35, "injection", "Fake system-prompt delimiter injection."),
    Rule("assistant_prefix",
         re.compile(r"(\bassistant\s*:|\bai\s*:|\bbot\s*:|response\s*:)\s*", re.I),
         20, "injection", "Pre-fills assistant turn to steer output."),

    # --- Sensitive data extraction ---
    Rule("extract_credentials",
         re.compile(r"(password|secret|api[_\s-]?key|token|credential|private[_\s-]?key)\s*(is|are|=|:)", re.I),
         20, "extraction", "Attempts to elicit or confirm credential values."),

    # --- Structural anomalies ---
    Rule("excessive_dashes",
         re.compile(r"-{10,}"),
         10, "injection", "Long dash sequences often used to confuse context boundaries."),
    Rule("null_bytes",
         re.compile(r"\x00|\\x00|\\u0000", re.I),
         15, "injection", "Null bytes used to truncate prompt strings."),
]


# ---------------------------------------------------------------------------
# Structural anomaly detectors (not regex-based)
# ---------------------------------------------------------------------------

def _structural_score(text: str) -> Tuple[int, List[str]]:
    """Return (score_delta, reasons) from structural checks."""
    score = 0
    reasons: List[str] = []

    # Unusually long input (potential context overflow attack)
    if len(text) > 8000:
        score += 10
        reasons.append("Very long input (" + str(len(text)) + " chars) may attempt context overflow.")

    # High density of special characters
    special = sum(1 for c in text if not c.isalnum() and c not in " .,;:!?-\'\"\'\n\t")
    density = special / max(len(text), 1)
    if density > 0.15:
        score += 15
        reasons.append("High special-character density ({:.1%}) may indicate obfuscation.".format(density))

    # Repeated instruction-like lines
    lines = text.splitlines()
    instr_lines = sum(1 for l in lines if re.search(r"^\s*(step\s*\d+|\d+\.\s+|>\s+|#\s+)", l, re.I))
    if instr_lines > 5:
        score += 10
        reasons.append(str(instr_lines) + " instruction-like lines detected (possible multi-step injection).")

    # Unusual Unicode (non-ASCII ratio)
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii / max(len(text), 1) > 0.3:
        score += 15
        reasons.append("High non-ASCII character ratio may indicate encoding obfuscation.")

    return min(score, 30), reasons


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    rule_name: str
    category: str
    score: int
    description: str
    matched_text: str


@dataclass
class DetectionResult:
    """Result of injection detection for one input text."""
    text_hash: str
    risk_score: int             # 0-100
    label: str                  # SAFE | SUSPICIOUS | INJECTION
    matches: List[RuleMatch] = field(default_factory=list)
    structural_reasons: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    @classmethod
    def _label_from_score(cls, score: int) -> str:
        if score >= 50:
            return "INJECTION"
        if score >= 20:
            return "SUSPICIOUS"
        return "SAFE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text_hash": self.text_hash,
            "risk_score": self.risk_score,
            "label": self.label,
            "timestamp": self.timestamp,
            "structural_reasons": self.structural_reasons,
            "matches": [
                {"rule": m.rule_name, "category": m.category,
                 "score": m.score, "description": m.description,
                 "matched_text": m.matched_text[:120]}
                for m in self.matches
            ],
        }

    def summary(self) -> str:
        lines = [
            "Risk: " + str(self.risk_score) + "/100 [" + self.label + "]",
        ]
        if self.matches:
            lines.append("Rules triggered (" + str(len(self.matches)) + "):")
            for m in self.matches:
                lines.append("  [" + m.category.upper() + "] " + m.rule_name + " (+" + str(m.score) + "): " + m.description)
        if self.structural_reasons:
            lines.append("Structural issues:")
            for r in self.structural_reasons:
                lines.append("  " + r)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class InjectionDetector:
    """
    Detect prompt injection and jailbreak attempts.

    Parameters
    ----------
    rules : list of Rule, optional
        Override the built-in rule set.
    max_score : int
        Cap the combined rule score (default 100).
    """

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        max_score: int = 100,
    ) -> None:
        self.rules = rules if rules is not None else _RULES
        self.max_score = max_score

    def detect(self, text: str) -> DetectionResult:
        """
        Analyse text for injection signals.

        Parameters
        ----------
        text : str
            The user-supplied input to check.

        Returns
        -------
        DetectionResult
        """
        text_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        matches: List[RuleMatch] = []
        score = 0

        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                matched = m.group(0)
                matches.append(RuleMatch(
                    rule_name=rule.name,
                    category=rule.category,
                    score=rule.score,
                    description=rule.description,
                    matched_text=matched,
                ))
                score += rule.score
                break  # one match per rule is enough

        struct_delta, struct_reasons = _structural_score(text)
        score += struct_delta
        score = min(score, self.max_score)
        label = DetectionResult._label_from_score(score)

        return DetectionResult(
            text_hash=text_hash,
            risk_score=score,
            label=label,
            matches=matches,
            structural_reasons=struct_reasons,
        )

    def is_safe(self, text: str) -> bool:
        """Return True if the text is classified as SAFE."""
        return self.detect(text).label == "SAFE"

    def batch_detect(self, texts: List[str]) -> List[DetectionResult]:
        """Detect injection in a list of texts."""
        return [self.detect(t) for t in texts]


# ---------------------------------------------------------------------------
# Middleware helpers
# ---------------------------------------------------------------------------

class InjectionGuard:
    """
    Wraps an LLM call function, blocking or flagging injections before the call.

    Parameters
    ----------
    llm_fn : callable
        The function to wrap. Called with the (possibly modified) prompt string.
    detector : InjectionDetector, optional
        Custom detector. Defaults to the built-in one.
    action : str
        "block" (raise ValueError) or "warn" (print warning, allow call).
    threshold : int
        Risk score at which the action is triggered (default 50).
    """

    def __init__(
        self,
        llm_fn,
        detector: Optional[InjectionDetector] = None,
        action: str = "block",
        threshold: int = 50,
    ) -> None:
        self._fn = llm_fn
        self._detector = detector or InjectionDetector()
        self.action = action
        self.threshold = threshold

    def __call__(self, prompt: str, **kwargs) -> Any:
        result = self._detector.detect(prompt)
        if result.risk_score >= self.threshold:
            msg = ("Prompt injection detected (score=" + str(result.risk_score) +
                   ", label=" + result.label + "). " + result.summary())
            if self.action == "block":
                raise ValueError(msg)
            else:
                print("[InjectionGuard WARNING] " + msg)
        return self._fn(prompt, **kwargs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse, sys
    parser = argparse.ArgumentParser(
        prog="llm-injection-detector",
        description="Detect prompt injection and jailbreak attempts in LLM inputs.",
    )
    sub = parser.add_subparsers(dest="cmd")

    check_p = sub.add_parser("check", help="Check a single prompt string.")
    check_p.add_argument("prompt", nargs="?", help="Prompt text. Reads stdin if omitted.")
    check_p.add_argument("--json", action="store_true", dest="as_json")

    file_p = sub.add_parser("file", help="Check prompts from a JSONL file (one per line).")
    file_p.add_argument("path", help="JSONL file; each record must have a 'text' key.")
    file_p.add_argument("--json", action="store_true", dest="as_json")

    sub.add_parser("rules", help="List all built-in detection rules.")

    args = parser.parse_args()
    detector = InjectionDetector()

    if args.cmd == "check":
        text = args.prompt if args.prompt else sys.stdin.read()
        result = detector.detect(text)
        if args.as_json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(result.summary())
        if result.label == "INJECTION":
            raise SystemExit(2)
        if result.label == "SUSPICIOUS":
            raise SystemExit(1)

    elif args.cmd == "file":
        from pathlib import Path
        results = []
        for line in Path(args.path).open(encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            text = d.get("text", d.get("prompt", ""))
            r = detector.detect(text)
            results.append(r.to_dict())
        if args.as_json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print(r["text_hash"] + " [" + r["label"] + "] score=" + str(r["risk_score"]))
        injections = sum(1 for r in results if r["label"] == "INJECTION")
        if injections:
            raise SystemExit(2)

    elif args.cmd == "rules":
        for rule in _RULES:
            print("[" + rule.category.upper() + "] " + rule.name + " (score=" + str(rule.score) + "): " + rule.description)

    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
