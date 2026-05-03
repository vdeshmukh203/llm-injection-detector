"""
Batch reporting utilities for llm-injection-detector.

DetectionReport aggregates multiple DetectionResult objects into a single
summary that can be serialised to JSON or printed as plain text.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .detector import DetectionResult, Label


@dataclass
class DetectionReport:
    """
    Aggregated report for a batch of detection results.

    Attributes:
        results: Individual DetectionResult objects.
        timestamp: UTC ISO-8601 timestamp of the report.
        label_counts: Count of SAFE / SUSPICIOUS / INJECTION labels.
        average_score: Mean score across all results.
        max_score: Highest individual score in the batch.
    """

    results: List[DetectionResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Computed on demand via properties

    @property
    def label_counts(self) -> Dict[str, int]:
        """Count of each label in the batch."""
        counts: Dict[str, int] = {"SAFE": 0, "SUSPICIOUS": 0, "INJECTION": 0}
        for r in self.results:
            counts[r.label.value] += 1
        return counts

    @property
    def average_score(self) -> float:
        """Mean detection score; returns 0.0 for an empty report."""
        if not self.results:
            return 0.0
        return sum(r.score for r in self.results) / len(self.results)

    @property
    def max_score(self) -> int:
        """Maximum detection score; returns 0 for an empty report."""
        return max((r.score for r in self.results), default=0)

    @property
    def flagged(self) -> List[DetectionResult]:
        """Results whose label is SUSPICIOUS or INJECTION."""
        return [r for r in self.results if r.label != Label.SAFE]

    def to_dict(self) -> Dict:
        """Serialise the full report to a plain Python dictionary."""
        return {
            "timestamp": self.timestamp,
            "summary": {
                "total": len(self.results),
                "label_counts": self.label_counts,
                "average_score": round(self.average_score, 2),
                "max_score": self.max_score,
            },
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the full report to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def summary_text(self) -> str:
        """Return a human-readable one-paragraph summary."""
        counts = self.label_counts
        lines = [
            f"Detection Report  [{self.timestamp[:19]} UTC]",
            f"  Total analysed : {len(self.results)}",
            f"  SAFE           : {counts['SAFE']}",
            f"  SUSPICIOUS     : {counts['SUSPICIOUS']}",
            f"  INJECTION      : {counts['INJECTION']}",
            f"  Average score  : {self.average_score:.1f}/100",
            f"  Maximum score  : {self.max_score}/100",
        ]
        return "\n".join(lines)
