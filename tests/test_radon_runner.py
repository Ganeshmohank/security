"""Smoke tests for the radon complexity engine."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("radon")

from secscan.engines.radon_runner import RadonRunner


def test_simple_function_is_not_flagged(tmp_path: Path):
    src = tmp_path / "simple.py"
    src.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert RadonRunner().analyze(src) == []


def test_branchy_function_is_flagged(tmp_path: Path):
    src = tmp_path / "busy.py"
    body = "def busy(x):\n"
    # Chain enough `if/elif` branches to push CC past grade B.
    for i in range(15):
        body += f"    {'if' if i == 0 else 'elif'} x == {i}:\n"
        body += f"        return {i}\n"
    body += "    return -1\n"
    src.write_text(body, encoding="utf-8")

    findings = RadonRunner().analyze(src)
    assert findings, "expected at least one complexity finding"
    assert findings[0].engine == "radon"
    assert findings[0].rule_id.startswith("CC-")
    assert findings[0].severity in {"low", "medium", "high", "critical"}


def test_min_grade_threshold_filters_results(tmp_path: Path):
    src = tmp_path / "mixed.py"
    body = "def busy(x):\n"
    for i in range(12):
        body += f"    {'if' if i == 0 else 'elif'} x == {i}:\n"
        body += f"        return {i}\n"
    body += "    return -1\n"
    src.write_text(body, encoding="utf-8")

    default_runner = RadonRunner(min_grade="C").analyze(src)
    strict_runner = RadonRunner(min_grade="F").analyze(src)

    assert default_runner  # default reports this as grade C or D
    assert strict_runner == []  # strict mode suppresses anything below F


def test_syntax_error_returns_info_finding(tmp_path: Path):
    src = tmp_path / "broken.py"
    src.write_text("def :\n", encoding="utf-8")
    findings = RadonRunner().analyze(src)
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].rule_id == "RADON-SYN"
