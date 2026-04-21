"""Smoke tests for ``secscan.report.builder``."""

from __future__ import annotations

import json

from secscan.core.finding import Finding
from secscan.core.scanner import ScanResult
from secscan.report.builder import ReportBuilder


def _sample_result() -> ScanResult:
    findings = [
        Finding(rule_id="SEC001", title="SQLi", severity="high",
                file="x.py", line=10, detail="bad exec", engine="ast"),
        Finding(rule_id="SEC002", title="Hardcoded secret", severity="critical",
                file="x.py", line=2, detail="API_KEY literal", engine="ast"),
    ]
    return ScanResult(file="x.py", findings=findings,
                      engine_counts={"ast": 2})


def test_text_report_contains_severity_tags():
    report = ReportBuilder([_sample_result()]).as_text()
    assert "secscan report" in report
    assert "crit" in report
    assert "high" in report
    assert "SEC001" in report


def test_json_report_is_valid_json_with_expected_keys():
    report = ReportBuilder([_sample_result()]).as_json()
    payload = json.loads(report)
    assert "generated" in payload
    assert payload["totals"]["ast"] == 2
    assert payload["results"][0]["file"] == "x.py"
    assert payload["results"][0]["findings"][0]["rule_id"] in {"SEC001", "SEC002"}


def test_html_report_has_severity_classes():
    report = ReportBuilder([_sample_result()]).as_html()
    assert "<html" in report
    assert "sev-crit" in report
    assert "sev-high" in report
    assert "SEC001" in report
    assert "x.py" in report


def test_html_report_uses_collapsible_file_sections():
    report = ReportBuilder([_sample_result()]).as_html()
    assert "<details" in report and "<summary" in report
    assert "sevbar" in report  # global severity bar


def test_html_report_contains_file_level_badges():
    report = ReportBuilder([_sample_result()]).as_html()
    # Crit and high counts surface as per-file badges in the summary row.
    assert "fb-crit" in report
    assert "fb-high" in report


def test_json_report_includes_severity_totals():
    report = ReportBuilder([_sample_result()]).as_json()
    payload = json.loads(report)
    assert "severity_totals" in payload
    assert payload["severity_totals"]["high"] == 1
    assert payload["severity_totals"]["critical"] == 1


def test_render_dispatch_defaults_to_text():
    rendered = ReportBuilder([_sample_result()]).render("unknown-format")
    assert "secscan report" in rendered


def test_empty_result_shows_no_findings_message():
    empty = ScanResult(file="empty.py", findings=[])
    text = ReportBuilder([empty]).as_text()
    assert "(no findings)" in text
