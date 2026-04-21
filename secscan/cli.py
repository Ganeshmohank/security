"""secscan command-line entry point.

Split into ``build_parser`` + ``run(args)`` so tests can drive the CLI
without spawning subprocesses. Adds two flags the old CLI lacked:

* ``--min-severity`` hides findings below a threshold.
* ``--fail-on``     makes the process exit non-zero when any finding at
                    or above the given severity exists. This is what a
                    CI job would gate on.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .core.finding import SEVERITY_ORDER
from .core.scanner import CodeScanner, ScanResult
from .report.builder import ReportBuilder


_SEVERITY_CHOICES = ("low", "medium", "high", "critical")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Static security scanner for Python source.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument("--no-bandit", action="store_true",
                        help="Skip the bandit engine")
    parser.add_argument("--no-radon", action="store_true",
                        help="Skip the radon complexity engine")
    parser.add_argument("--radon-min-grade", default="C",
                        choices=tuple("ABCDEF"),
                        help="Lowest radon grade that produces a finding "
                             "(default: C)")
    parser.add_argument("--llm", action="store_true",
                        help="Enable LLM review via OpenRouter "
                             "(needs OPENROUTER_API_KEY)")
    parser.add_argument("--model", default="deepseek/deepseek-chat",
                        help="OpenRouter model id (default: deepseek/deepseek-chat)")
    parser.add_argument("-o", "--output", type=Path,
                        help="Write the report to this path instead of stdout")
    parser.add_argument("-f", "--format", choices=("text", "json", "html"),
                        default="text", help="Report format (default: text)")
    parser.add_argument("--min-severity", choices=_SEVERITY_CHOICES,
                        default="low",
                        help="Hide findings below this severity "
                             "(default: low = show everything)")
    parser.add_argument("--fail-on", choices=_SEVERITY_CHOICES,
                        default=None,
                        help="Exit with code 1 when any finding at or above "
                             "this severity is present (useful in CI)")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target: Path = args.target
    if not target.exists():
        parser.error(f"target does not exist: {target}")

    scanner = CodeScanner(
        use_llm=args.llm,
        llm_model=args.model,
        use_bandit=not args.no_bandit,
        use_radon=not args.no_radon,
        radon_min_grade=args.radon_min_grade,
    )

    print(f"scanning {target}...", file=sys.stderr)
    results = scanner.scan(target)

    if args.min_severity != "low":
        threshold = SEVERITY_ORDER[args.min_severity]
        results = _filter_results(results, threshold)

    report = ReportBuilder(results)
    rendered = report.render(args.format)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
        if args.format == "text":
            sys.stdout.write("\n")

    _print_summary(results)

    if args.fail_on:
        if _any_at_or_above(results, SEVERITY_ORDER[args.fail_on]):
            return 1
    return 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _filter_results(results, threshold: int):
    trimmed = []
    for r in results:
        kept = [f for f in r.findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]
        r.findings = kept
        r.confirmed = [f for f in r.confirmed if SEVERITY_ORDER.get(f.severity, 0) >= threshold]
        r.engine_counts = {}
        for f in kept:
            r.engine_counts[f.engine] = r.engine_counts.get(f.engine, 0) + 1
        trimmed.append(r)
    return trimmed


def _any_at_or_above(results, threshold: int) -> bool:
    for r in results:
        for f in r.findings:
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold:
                return True
    return False


def _print_summary(results) -> None:
    files = len(results)
    ast = sum(len(r.findings_by_engine("ast")) for r in results)
    bandit = sum(len(r.findings_by_engine("bandit")) for r in results)
    radon = sum(len(r.findings_by_engine("radon")) for r in results)
    llm = sum(len(r.findings_by_engine("llm")) for r in results)
    confirmed = sum(len(r.confirmed) for r in results)
    print(
        f"\nfiles={files}  ast={ast}  bandit={bandit}  radon={radon}  "
        f"llm={llm}  confirmed={confirmed}",
        file=sys.stderr,
    )


def main() -> None:  # pragma: no cover
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
