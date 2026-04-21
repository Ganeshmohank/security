"""Scanner-level tests.

The bandit engine is disabled here so the tests do not depend on a local
bandit binary; rule coverage is covered separately in
``tests/test_ast_rules.py``.
"""

from __future__ import annotations

from pathlib import Path

from secscan.core.finding import Finding
from secscan.core.scanner import CodeScanner


FIXTURES = Path(__file__).resolve().parent.parent / "test_code"


def _scan(target: Path):
    return CodeScanner(use_bandit=False, use_llm=False).scan(target)


def test_scan_single_file_returns_findings():
    results = _scan(FIXTURES / "database.py")
    assert len(results) == 1
    assert any(f.rule_id == "SEC001" for f in results[0].findings)
    assert any(f.rule_id == "SEC005" for f in results[0].findings)


def test_scan_directory_walks_every_python_file():
    results = _scan(FIXTURES)
    files = {Path(r.file).name for r in results}
    assert {"app.py", "config.py", "database.py", "templates.py", "utils.py"}.issubset(files)


def test_scan_skips_pycache(tmp_path: Path):
    pkg = tmp_path / "__pycache__"
    pkg.mkdir()
    (pkg / "ignored.py").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "real.py").write_text("eval(x)\n", encoding="utf-8")

    results = _scan(tmp_path)
    names = {Path(r.file).name for r in results}
    assert names == {"real.py"}


def test_scan_result_to_dict_roundtrip():
    results = _scan(FIXTURES / "app.py")
    payload = results[0].to_dict()
    assert "findings" in payload and "file" in payload
    assert "ast_results" in payload  # backwards-compatible key


def test_confirmed_requires_multiple_engines():
    # All findings here come from the AST engine only; nothing should end up
    # in the confirmed bucket.
    results = _scan(FIXTURES / "app.py")
    assert results[0].confirmed == []


def test_confirmed_fires_when_two_engines_agree():
    # Hand-build two findings on the same rough line from different engines
    # and feed them through the dedupe helper.
    from secscan.core.scanner import _find_confirmed

    a = Finding(rule_id="SEC001", title="SQLi", severity="high",
                file="x.py", line=12, detail="", engine="ast")
    b = Finding(rule_id="B608", title="sql injection", severity="high",
                file="x.py", line=12, detail="", engine="bandit")
    assert len(_find_confirmed([a, b])) == 1
