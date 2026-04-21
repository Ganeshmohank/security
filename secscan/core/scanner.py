"""Top-level scan orchestration.

Each file goes through three optional pipes (AST rules, bandit, LLM).
Their ``Finding`` lists are merged into a ``ScanResult`` with a dedupe
step that marks issues as ``confirmed`` when multiple engines flag the
same (rule-ish, line) pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from .finding import Finding, SEVERITY_ORDER
from ..engines.bandit_runner import BanditRunner
from ..engines.llm_client import LlmReviewer
from ..engines.radon_runner import RadonRunner
from ..rules.ast_rules import run_rules


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    file: str
    findings: List[Finding] = field(default_factory=list)
    confirmed: List[Finding] = field(default_factory=list)
    engine_counts: dict[str, int] = field(default_factory=dict)

    def findings_by_engine(self, engine: str) -> List[Finding]:
        return [f for f in self.findings if f.engine == engine]

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "findings": [f.to_dict() for f in self.findings],
            "confirmed": [f.to_dict() for f in self.confirmed],
            "engine_counts": self.engine_counts,
            # Backwards-compatible keys used by the old JSON consumers.
            "ast_results": [f.to_dict() for f in self.findings_by_engine("ast")],
            "bandit_results": [f.to_dict() for f in self.findings_by_engine("bandit")],
            "llm_results": [f.to_dict() for f in self.findings_by_engine("llm")],
            "radon_results": [f.to_dict() for f in self.findings_by_engine("radon")],
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


_SKIP_PARTS = {"__pycache__", "venv", ".venv", "env", ".git", "node_modules"}


class CodeScanner:
    """Coordinator for all analysis engines."""

    def __init__(
        self,
        *,
        use_llm: bool = False,
        llm_api_key: Optional[str] = None,
        llm_model: str = "deepseek/deepseek-chat",
        use_bandit: bool = True,
        use_radon: bool = True,
        radon_min_grade: str = "C",
    ) -> None:
        self.use_llm = use_llm
        self.use_bandit = use_bandit
        self.use_radon = use_radon
        self.bandit = BanditRunner() if use_bandit else None
        self.llm = LlmReviewer(api_key=llm_api_key, model=llm_model) if use_llm else None
        self.radon = RadonRunner(min_grade=radon_min_grade) if use_radon else None

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> ScanResult:
        file_path = Path(file_path)
        findings: list[Finding] = []
        findings.extend(run_rules(file_path))
        if self.bandit is not None:
            findings.extend(self.bandit.analyze(file_path))
        if self.radon is not None:
            findings.extend(self.radon.analyze(file_path))
        if self.llm is not None:
            findings.extend(self.llm.analyze(file_path))

        result = ScanResult(file=str(file_path), findings=findings)
        result.engine_counts = _tally_engines(findings)
        result.confirmed = _find_confirmed(findings)
        return result

    def scan_directory(self, directory: Path) -> List[ScanResult]:
        directory = Path(directory)
        out: list[ScanResult] = []
        for py_file in sorted(directory.rglob("*.py")):
            if any(part in _SKIP_PARTS for part in py_file.parts):
                continue
            out.append(self.scan_file(py_file))
        return out

    def scan(self, target: Path) -> List[ScanResult]:
        target = Path(target)
        if target.is_file():
            return [self.scan_file(target)]
        return self.scan_directory(target)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tally_engines(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.engine] = counts.get(f.engine, 0) + 1
    return counts


def _key(finding: Finding) -> tuple[str, int]:
    """A loose identity key for dedupe: normalise the rule_id or title,
    then bucket by line. Returning only 2 fields lets us match across
    engines (ast SEC001 vs bandit SQLi both sit on line 24 -> same key)."""
    token = (
        f"{finding.rule_id or ''} {finding.title or ''} {finding.detail or ''}"
    ).lower()
    for needle, canon in (
        ("sql", "sqli"),
        ("injection", "sqli"),
        ("secret", "secret"),
        ("credential", "secret"),
        ("eval", "dangerous"),
        ("exec", "dangerous"),
        ("pickle", "dangerous"),
        ("shell", "dangerous"),
        ("yaml", "dangerous"),
        ("debug", "debug"),
        ("jinja", "xss"),
        ("hash", "crypto"),
        ("md5", "crypto"),
        ("sha1", "crypto"),
    ):
        if needle in token:
            token = canon
            break
    return token, finding.line


def _find_confirmed(findings: Iterable[Finding]) -> List[Finding]:
    """Return one representative per (key, +/-1 line) group that was flagged
    by more than one engine."""
    groups: dict[tuple[str, int], list[Finding]] = {}
    for f in findings:
        if f.severity == "error" or f.severity == "info":
            continue
        key = _key(f)
        # Widen the line match by +/- 1 line by bucketing to nearest even number.
        bucketed = (key[0], key[1] // 2)
        groups.setdefault(bucketed, []).append(f)

    confirmed: list[Finding] = []
    for items in groups.values():
        if len({f.engine for f in items}) >= 2:
            # Promote the highest-severity finding as the representative.
            pick = max(items, key=lambda f: SEVERITY_ORDER.get(f.severity, 0))
            confirmed.append(pick)
    return confirmed
