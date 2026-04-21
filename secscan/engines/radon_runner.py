"""Radon-based complexity engine.

Functions whose cyclomatic complexity exceeds ``threshold`` are flagged.
High complexity is not itself a vulnerability, but it strongly correlates
with hard-to-audit code paths, so the course brief (which names ``radon``
alongside ``ast`` and ``bandit``) treats it as a useful signal for review.

This engine runs the ``radon`` library in-process (no subprocess), so it
is cheap and works offline.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..core.finding import Finding


# Thresholds mirror the radon CLI letter-grades:
#   A: 1-5    trivial
#   B: 6-10   well-written
#   C: 11-20  slightly complex          <- warn
#   D: 21-30  more than slightly        <- flag medium
#   E: 31-40  complex                   <- flag high
#   F: 41+    unmaintainable            <- flag critical
_GRADE_TO_SEVERITY = {
    "A": None,
    "B": None,
    "C": "low",
    "D": "medium",
    "E": "high",
    "F": "critical",
}


class RadonRunner:
    """Run radon cyclomatic-complexity over a single file."""

    def __init__(self, min_grade: str = "C") -> None:
        self.min_grade = min_grade.upper()

    def analyze(self, file_path: Path) -> List[Finding]:
        try:
            from radon.complexity import cc_visit, cc_rank
        except ImportError:
            return [
                Finding(
                    rule_id="RADON-MISS",
                    title="radon not installed",
                    severity="info",
                    file=str(file_path),
                    line=0,
                    detail="Install with: pip install radon",
                    engine="radon",
                )
            ]

        try:
            source = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            return [self._error(file_path, f"Cannot read: {exc}")]

        try:
            blocks = cc_visit(source)
        except SyntaxError as exc:
            return [
                Finding(
                    rule_id="RADON-SYN",
                    title="radon: syntax error",
                    severity="info",
                    file=str(file_path),
                    line=exc.lineno or 0,
                    detail=str(exc.msg),
                    engine="radon",
                )
            ]

        out: list[Finding] = []
        for blk in blocks:
            grade = cc_rank(blk.complexity)
            severity = _GRADE_TO_SEVERITY.get(grade)
            if severity is None:
                continue
            if self._below_min_grade(grade):
                continue
            out.append(
                Finding(
                    rule_id=f"CC-{grade}",
                    title=f"High cyclomatic complexity ({blk.complexity})",
                    severity=severity,
                    file=str(file_path),
                    line=blk.lineno,
                    detail=(
                        f"{_kind(blk)} {blk.name!r} has CC={blk.complexity} "
                        f"(grade {grade}). Consider splitting into smaller "
                        "helpers; reviewers have a harder time reasoning about "
                        "security properties of large branching functions."
                    ),
                    engine="radon",
                    extra={"grade": grade, "complexity": blk.complexity,
                           "kind": _kind(blk)},
                )
            )
        return out

    def _below_min_grade(self, grade: str) -> bool:
        order = ["A", "B", "C", "D", "E", "F"]
        return order.index(grade) < order.index(self.min_grade)

    @staticmethod
    def _error(file_path: Path, detail: str) -> Finding:
        return Finding(
            rule_id="RADON-ERR",
            title="radon engine error",
            severity="info",
            file=str(file_path),
            line=0,
            detail=detail,
            engine="radon",
        )


def _kind(block) -> str:
    # radon blocks come in a few flavours; map to readable labels without
    # importing the private class hierarchy.
    cls = type(block).__name__.lower()
    if "method" in cls:
        return "method"
    if "class" in cls:
        return "class"
    return "function"
