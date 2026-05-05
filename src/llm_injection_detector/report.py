"""
Structured report aggregation for batch detection runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Dict, Any

from llm_injection_detector import DetectionResult, Label


@dataclass
class DetectionReport:
    """
    Aggregated report over a collection of :class:`DetectionResult` objects.

    Attributes
    ----------
    results : list of DetectionResult
        Individual per-text results.
    total : int
        Total number of texts analysed.
    safe_count : int
        Number of texts labelled SAFE.
    suspicious_count : int
        Number of texts labelled SUSPICIOUS.
    injection_count : int
        Number of texts labelled INJECTION.
    summary : dict
        High-level statistics dictionary.
    """

    results: List[DetectionResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def safe_count(self) -> int:
        return sum(1 for r in self.results if r.label == Label.SAFE)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for r in self.results if r.label == Label.SUSPICIOUS)

    @property
    def injection_count(self) -> int:
        return sum(1 for r in self.results if r.label == Label.INJECTION)

    @property
    def summary(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "safe": self.safe_count,
            "suspicious": self.suspicious_count,
            "injection": self.injection_count,
            "injection_rate": (
                round(self.injection_count / self.total, 4) if self.total else 0.0
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full report to a plain dictionary."""
        return {
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the full report to an indented JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"DetectionReport(total={self.total}, safe={self.safe_count}, "
            f"suspicious={self.suspicious_count}, injection={self.injection_count})"
        )
