"""Render scan results as plain text, JSON, or HTML.

The HTML renderer in this revision adds three quality-of-life features
over the previous one:

* A top stat bar with cross-severity totals.
* Collapsible per-file ``<details>`` sections (native HTML, no JS).
* A 3-line source snippet around each finding, with the exact line
  highlighted.
"""

from __future__ import annotations

import html as html_lib
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, List

from ..core.finding import Finding, SEVERITY_ORDER
from ..core.scanner import ScanResult


_SEVERITY_BADGES = {
    "critical": "crit",
    "high": "high",
    "medium": "med",
    "low": "low",
    "info": "info",
    "error": "err",
}

_SEVERITY_DISPLAY_ORDER = ("critical", "high", "medium", "low", "info")

_SNIPPET_CONTEXT_LINES = 1


class ReportBuilder:
    """Wraps a list of ``ScanResult`` and emits formatted reports."""

    def __init__(self, results: List[ScanResult]) -> None:
        self.results = results

    # ------------------------------------------------------------------
    # text
    # ------------------------------------------------------------------

    def as_text(self) -> str:
        lines: list[str] = []
        lines.append("secscan report")
        lines.append(f"generated: {datetime.now():%Y-%m-%d %H:%M:%S}")
        lines.append("")

        totals = self._totals()
        lines.append(
            "files={files}  ast={ast}  bandit={bandit}  radon={radon}  "
            "llm={llm}  confirmed={confirmed}".format(**totals)
        )
        sev_totals = self._severity_totals()
        lines.append(
            "severity  " + "  ".join(
                f"{s}={sev_totals[s]}" for s in _SEVERITY_DISPLAY_ORDER
            )
        )
        lines.append("-" * 72)

        for result in self.results:
            lines.append("")
            lines.append(f"* {result.file}")
            if not result.findings:
                lines.append("    (no findings)")
                continue

            per_file = _count_severity(result.findings)
            parts = [f"{s}:{per_file[s]}" for s in _SEVERITY_DISPLAY_ORDER if per_file[s]]
            if parts:
                lines.append("    [" + "  ".join(parts) + "]")

            for f in _sorted(result.findings):
                tag = _SEVERITY_BADGES.get(f.severity, f.severity)
                lines.append(
                    f"  [{tag:<4}] {f.engine:<6} L{f.line:<4} {f.rule_id:<10} {f.title}"
                )
                lines.append(f"          {_wrap(f.detail, 80, indent=10)}")
            if result.confirmed:
                lines.append(f"    -> cross-engine confirmed: {len(result.confirmed)}")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # json
    # ------------------------------------------------------------------

    def as_json(self) -> str:
        payload = {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "totals": self._totals(),
            "severity_totals": self._severity_totals(),
            "results": [r.to_dict() for r in self.results],
        }
        return json.dumps(payload, indent=2)

    # ------------------------------------------------------------------
    # html
    # ------------------------------------------------------------------

    def as_html(self) -> str:
        totals = self._totals()
        sev = self._severity_totals()
        parts: list[str] = [
            "<!doctype html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='utf-8'>",
            "<title>secscan report</title>",
            f"<style>{_CSS}</style>",
            "</head>",
            "<body>",
            "<main class='wrap'>",
            "<header class='hero'>",
            "<h1>secscan report</h1>",
            f"<p class='sub'>generated {html_lib.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>",
            "</header>",
            "<section class='stats'>",
            _stat("files", totals["files"]),
            _stat("ast", totals["ast"]),
            _stat("bandit", totals["bandit"]),
            _stat("radon", totals["radon"]),
            _stat("llm", totals["llm"]),
            _stat("confirmed", totals["confirmed"], "confirmed"),
            "</section>",
            "<section class='sevbar'>",
            "<span class='sb-label'>severity</span>",
        ]
        for lvl in _SEVERITY_DISPLAY_ORDER:
            parts.append(
                f"<span class='sb sb-{_SEVERITY_BADGES.get(lvl, lvl)}'>"
                f"<b>{sev[lvl]}</b> {html_lib.escape(lvl)}"
                f"</span>"
            )
        parts.append("</section>")

        for result in self.results:
            per_file = _count_severity(result.findings)
            crit_or_high = per_file["critical"] + per_file["high"]
            header_classes = "file"
            if crit_or_high:
                header_classes += " has-critical"

            parts.append(f"<details open class='{header_classes}'>")
            parts.append("<summary>")
            parts.append(f"<span class='fname'>{html_lib.escape(result.file)}</span>")
            parts.append("<span class='fbadges'>")
            for lvl in _SEVERITY_DISPLAY_ORDER:
                if per_file[lvl]:
                    parts.append(
                        f"<span class='fb fb-{_SEVERITY_BADGES.get(lvl, lvl)}'>"
                        f"{per_file[lvl]} {lvl[0].upper()}</span>"
                    )
            parts.append("</span>")
            parts.append("</summary>")

            if not result.findings:
                parts.append("<p class='empty'>No findings.</p>")
            else:
                source_lines = _read_lines(result.file)
                parts.append("<ul class='findings'>")
                for f in _sorted(result.findings):
                    parts.append(_render_finding(f, source_lines))
                parts.append("</ul>")
                if result.confirmed:
                    parts.append(
                        f"<p class='confirmed'>{len(result.confirmed)} cross-engine confirmed finding(s)</p>"
                    )
            parts.append("</details>")

        parts.append("</main></body></html>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def write(self, path: Path, fmt: str = "text") -> None:
        payload = self.render(fmt)
        Path(path).write_text(payload, encoding="utf-8")

    def render(self, fmt: str = "text") -> str:
        fmt = fmt.lower()
        if fmt == "json":
            return self.as_json()
        if fmt == "html":
            return self.as_html()
        return self.as_text()

    # ------------------------------------------------------------------
    # stats
    # ------------------------------------------------------------------

    def _totals(self) -> dict[str, int]:
        t = {"files": len(self.results), "ast": 0, "bandit": 0,
             "radon": 0, "llm": 0, "confirmed": 0}
        for r in self.results:
            t["ast"] += len(r.findings_by_engine("ast"))
            t["bandit"] += len(r.findings_by_engine("bandit"))
            t["radon"] += len(r.findings_by_engine("radon"))
            t["llm"] += len(r.findings_by_engine("llm"))
            t["confirmed"] += len(r.confirmed)
        return t

    def _severity_totals(self) -> dict[str, int]:
        tally = {lvl: 0 for lvl in _SEVERITY_DISPLAY_ORDER}
        for r in self.results:
            for f in r.findings:
                if f.severity in tally:
                    tally[f.severity] += 1
        return tally


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sorted(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.line, f.rule_id),
    )


def _count_severity(findings: Iterable[Finding]) -> dict[str, int]:
    out = {lvl: 0 for lvl in _SEVERITY_DISPLAY_ORDER}
    for f in findings:
        if f.severity in out:
            out[f.severity] += 1
    return out


def _wrap(text: str, width: int, indent: int) -> str:
    pad = " " * indent
    words = text.split()
    line = ""
    buf: list[str] = []
    for w in words:
        if len(line) + len(w) + 1 > width:
            buf.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        buf.append(line)
    return f"\n{pad}".join(buf)


def _stat(label: str, value: int, extra_class: str = "") -> str:
    extra = f" {extra_class}" if extra_class else ""
    return (
        f"<div class='stat{extra}'>"
        f"<span class='n'>{value}</span>"
        f"<span class='l'>{html_lib.escape(label)}</span>"
        "</div>"
    )


def _read_lines(path: str) -> list[str] | None:
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None


def _render_finding(f: Finding, source_lines: list[str] | None) -> str:
    badge = _SEVERITY_BADGES.get(f.severity, f.severity)
    snippet_html = _render_snippet(f.line, source_lines)
    return (
        f"<li class='f sev-{html_lib.escape(badge)}'>"
        f"<div class='row'>"
        f"<span class='sev'>{html_lib.escape(f.severity.upper())}</span>"
        f"<span class='rid'>{html_lib.escape(f.rule_id)}</span>"
        f"<span class='eng'>{html_lib.escape(f.engine)}</span>"
        f"<span class='ln'>L{f.line}</span>"
        f"<span class='ti'>{html_lib.escape(f.title)}</span>"
        "</div>"
        f"<p class='dt'>{html_lib.escape(f.detail)}</p>"
        f"{snippet_html}"
        "</li>"
    )


def _render_snippet(line: int, source_lines: list[str] | None) -> str:
    if not source_lines or line <= 0 or line > len(source_lines):
        return ""
    lo = max(1, line - _SNIPPET_CONTEXT_LINES)
    hi = min(len(source_lines), line + _SNIPPET_CONTEXT_LINES)
    rows = []
    for n in range(lo, hi + 1):
        raw = source_lines[n - 1].rstrip()
        marker = "focus" if n == line else ""
        rows.append(
            f"<span class='code-row {marker}'>"
            f"<span class='code-no'>{n}</span>"
            f"<span class='code-txt'>{html_lib.escape(raw) or '&nbsp;'}</span>"
            f"</span>"
        )
    return "<pre class='snippet'>" + "".join(rows) + "</pre>"


_CSS = """
:root {
    --bg: #0f1115;
    --panel: #171a21;
    --panel2: #1d2129;
    --panel3: #232936;
    --ink: #e7ecf3;
    --muted: #8a92a1;
    --accent: #6ea8fe;
    --crit: #ff5d5d;
    --high: #ffa048;
    --med:  #ffd166;
    --low:  #7bd389;
    --info: #8ab4f8;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 20px 80px; }
.hero h1 { margin: 0; font-size: 28px; letter-spacing: 0.2px; }
.hero .sub { margin: 4px 0 24px; color: var(--muted); font-size: 13px; }
.stats { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-bottom: 14px; }
.stat { background: var(--panel); padding: 14px 16px; border-radius: 10px; border: 1px solid var(--panel3); }
.stat .n { display: block; font-size: 24px; font-weight: 700; }
.stat .l { display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); }
.stat.confirmed { border-color: #3a5aa6; }
.sevbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; background: var(--panel); border: 1px solid var(--panel3); border-radius: 10px; padding: 10px 14px; margin-bottom: 22px; }
.sb-label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; margin-right: 4px; }
.sb { font-size: 12px; padding: 4px 10px; border-radius: 999px; background: rgba(255,255,255,0.05); color: var(--muted); }
.sb b { color: var(--ink); margin-right: 4px; }
.sb-crit { background: rgba(255, 93, 93, 0.18); color: var(--crit); }
.sb-high { background: rgba(255, 160, 72, 0.18); color: var(--high); }
.sb-med  { background: rgba(255, 209, 102, 0.18); color: var(--med); }
.sb-low  { background: rgba(123, 211, 137, 0.18); color: var(--low); }
.sb-info { background: rgba(138, 180, 248, 0.18); color: var(--info); }

details.file { background: var(--panel); border: 1px solid var(--panel3); border-radius: 12px; padding: 0; margin: 12px 0; overflow: hidden; }
details.file.has-critical { border-color: rgba(255, 93, 93, 0.45); }
details.file > summary { cursor: pointer; padding: 14px 18px; display: flex; align-items: center; gap: 12px; justify-content: space-between; list-style: none; }
details.file > summary::-webkit-details-marker { display: none; }
details.file > summary::before { content: '\\25B8'; color: var(--muted); transition: transform 0.15s ease; }
details.file[open] > summary::before { transform: rotate(90deg); display: inline-block; }
.fname { color: var(--accent); font-family: ui-monospace, SFMono-Regular, monospace; font-size: 14px; word-break: break-all; flex: 1; }
.fbadges { display: flex; gap: 6px; flex-shrink: 0; }
.fb { font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600; }
.fb-crit { background: rgba(255, 93, 93, 0.18); color: var(--crit); }
.fb-high { background: rgba(255, 160, 72, 0.18); color: var(--high); }
.fb-med  { background: rgba(255, 209, 102, 0.18); color: var(--med); }
.fb-low  { background: rgba(123, 211, 137, 0.18); color: var(--low); }
.fb-info { background: rgba(138, 180, 248, 0.18); color: var(--info); }

.findings { list-style: none; margin: 0; padding: 0 18px 14px; }
.f { background: var(--panel2); border-left: 4px solid var(--muted); border-radius: 6px; padding: 10px 12px; margin: 8px 0; }
.f .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; font-size: 12.5px; }
.f .sev { font-weight: 700; font-size: 11px; letter-spacing: 0.6px; padding: 2px 8px; border-radius: 999px; background: rgba(255,255,255,0.05); }
.f .rid, .f .eng, .f .ln { color: var(--muted); font-family: ui-monospace, monospace; }
.f .ti { font-weight: 600; }
.f .dt { margin: 6px 0 0; color: #cfd5df; font-size: 13px; }
.f.sev-crit { border-left-color: var(--crit); }
.f.sev-crit .sev { background: rgba(255, 93, 93, 0.15); color: var(--crit); }
.f.sev-high { border-left-color: var(--high); }
.f.sev-high .sev { background: rgba(255, 160, 72, 0.15); color: var(--high); }
.f.sev-med { border-left-color: var(--med); }
.f.sev-med .sev { background: rgba(255, 209, 102, 0.15); color: var(--med); }
.f.sev-low { border-left-color: var(--low); }
.f.sev-low .sev { background: rgba(123, 211, 137, 0.15); color: var(--low); }
.f.sev-info { border-left-color: var(--info); }
.f.sev-info .sev { background: rgba(138, 180, 248, 0.15); color: var(--info); }
.snippet { background: #0c0f14; border: 1px solid var(--panel3); border-radius: 6px; margin: 10px 0 0; padding: 8px 0; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12.5px; overflow-x: auto; }
.code-row { display: block; padding: 1px 12px; white-space: pre; }
.code-row.focus { background: rgba(255, 160, 72, 0.12); border-left: 2px solid var(--high); padding-left: 10px; }
.code-no { color: var(--muted); width: 3em; display: inline-block; text-align: right; margin-right: 12px; user-select: none; }
.code-txt { color: var(--ink); }
.empty { color: var(--muted); font-style: italic; padding: 0 18px 14px; }
.confirmed { color: var(--accent); font-size: 12.5px; margin: 10px 18px 14px; }
@media (max-width: 760px) {
    .stats { grid-template-columns: repeat(3, 1fr); }
}
"""
