"""Shared data contract returned by every detection engine.

A `Finding` is the only type crossing module boundaries. Rule modules and
engine wrappers build them, the scanner aggregates them, and the report
builder renders them. Keeping this tiny and stable is what lets Teammate A
and Teammate B work in parallel.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Literal, Dict, Any


Severity = Literal["info", "low", "medium", "high", "critical", "error"]

# Lowest to highest. Used for threshold filters and comparisons.
SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "error": 5,  # analyzer errors, not user-facing severity
}


@dataclass
class Finding:
    """One vulnerability (or analyzer note) reported by any engine."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    detail: str
    engine: str = "ast"
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        # Flatten for JSON reports while staying backward compatible
        # with the older `type / message / description` field names.
        payload = asdict(self)
        payload["type"] = self.title
        payload["message"] = self.title
        payload["description"] = self.detail
        return payload

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)
