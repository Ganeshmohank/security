"""Thin wrapper around the ``bandit`` CLI.

We do not re-implement bandit; we shell out to it, parse its JSON output,
and keep only a curated subset of test IDs so the report stays focused.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List

from ..core.finding import Finding


# Curated subset of bandit tests. Keeping this in one dict makes it easy
# to enable or relabel checks later.
KEY_TESTS: dict[str, dict[str, str]] = {
    "B201": {"label": "Flask debug mode", "severity": "high"},
    "B506": {"label": "Unsafe yaml.load", "severity": "medium"},
    "B602": {"label": "Subprocess shell=True", "severity": "high"},
    "B701": {"label": "Jinja2 autoescape=False", "severity": "high"},
}


_SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


class BanditRunner:
    """Invokes ``bandit -f json`` and normalises the result."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def analyze(self, file_path: Path) -> List[Finding]:
        try:
            proc = subprocess.run(
                ["bandit", "-f", "json", "-ll", str(file_path)],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return [self._as_error(file_path, "Bandit not installed",
                                    "Install with: pip install bandit")]
        except subprocess.TimeoutExpired:
            return [self._as_error(file_path, "Bandit timed out",
                                    f"bandit exceeded {self.timeout}s on this file")]
        except Exception as exc:
            return [self._as_error(file_path, "Bandit error", str(exc))]

        if not proc.stdout:
            # Nothing to parse; surface stderr if any.
            msg = (proc.stderr or "bandit produced no output").strip()[:200]
            return [self._as_error(file_path, "Bandit error", msg)]

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return [self._as_error(file_path, "Bandit output unparseable",
                                    proc.stderr[:200] if proc.stderr else "")]

        return list(self._translate(payload, file_path))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _translate(self, payload: dict, file_path: Path):
        for item in payload.get("results", []):
            test_id = item.get("test_id", "")
            if test_id not in KEY_TESTS:
                continue
            meta = KEY_TESTS[test_id]
            yield Finding(
                rule_id=test_id,
                title=meta["label"],
                severity=_SEVERITY_MAP.get(item.get("issue_severity", "MEDIUM"),
                                            meta["severity"]),
                file=item.get("filename", str(file_path)),
                line=item.get("line_number", 0) or 0,
                detail=item.get("issue_text", "Bandit flagged this line."),
                engine="bandit",
                extra={
                    "confidence": item.get("issue_confidence", ""),
                    "cwe": (item.get("issue_cwe") or {}).get("id", ""),
                },
            )

    @staticmethod
    def _as_error(file_path: Path, title: str, detail: str) -> Finding:
        return Finding(
            rule_id="BANDIT-ERR",
            title=title,
            severity="info",
            file=str(file_path),
            line=0,
            detail=detail,
            engine="bandit",
        )
