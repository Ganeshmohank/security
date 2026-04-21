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
import os
import sys
from pathlib import Path
from typing import Sequence

from .core.finding import SEVERITY_ORDER
from .core.scanner import CodeScanner, ScanResult
from .report.builder import ReportBuilder


def _load_dotenv(path: Path) -> None:
    """Best-effort `.env` loader. Pulls simple ``KEY=value`` lines into
    ``os.environ`` unless they are already set. Lines that start with
    ``#`` or are blank are skipped. Values may be wrapped in single or
    double quotes. Placeholder tokens (``your_*`` / ``changeme``) are
    ignored so the user does not accidentally activate them.
    """
    if not path.is_file():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if not key or not value:
                continue
            if value.lower().startswith(("your_", "changeme", "<")):
                continue
            os.environ[key] = value
    except OSError:
        return


_SEVERITY_CHOICES = ("low", "medium", "high", "critical")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Static security scanner for Python source.",
    )
    parser.add_argument("target", nargs="?", type=Path,
                        help="File or directory to scan")
    parser.add_argument("--check-llm", action="store_true",
                        help="Don't scan; just verify the LLM provider + API "
                             "key by making a single tiny request.")
    parser.add_argument("--no-bandit", action="store_true",
                        help="Skip the bandit engine")
    parser.add_argument("--no-radon", action="store_true",
                        help="Skip the radon complexity engine")
    parser.add_argument("--radon-min-grade", default="C",
                        choices=tuple("ABCDEF"),
                        help="Lowest radon grade that produces a finding "
                             "(default: C)")
    parser.add_argument("--llm", action="store_true",
                        help="Enable LLM-assisted review "
                             "(needs OPENAI_API_KEY or OPENROUTER_API_KEY)")
    parser.add_argument("--provider", choices=("auto", "openai", "openrouter"),
                        default="auto",
                        help="Which LLM provider to call (default: auto — "
                             "picks OpenAI if OPENAI_API_KEY is set, else "
                             "OpenRouter)")
    parser.add_argument("--api-key", default=None,
                        help="Override the LLM API key for this run "
                             "(otherwise read from env or .env file)")
    parser.add_argument("--model", default=None,
                        help="Model id (default depends on provider: "
                             "gpt-4o-mini for openai, "
                             "deepseek/deepseek-chat for openrouter)")
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

    _load_dotenv(Path.cwd() / ".env")

    if args.check_llm:
        return _check_llm(args)

    target: Path = args.target
    if target is None:
        parser.error("target is required (unless --check-llm is passed)")
    if not target.exists():
        parser.error(f"target does not exist: {target}")

    scanner = CodeScanner(
        use_llm=args.llm,
        llm_model=args.model,
        llm_provider=args.provider,
        llm_api_key=args.api_key,
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


def _check_llm(args) -> int:
    """One-shot connectivity + auth check for the configured LLM."""
    from .engines.llm_client import LlmReviewer

    reviewer = LlmReviewer(
        api_key=args.api_key,
        model=args.model,
        provider=args.provider,
    )
    key = reviewer.api_key
    print(f"provider: {reviewer.provider}", file=sys.stderr)
    print(f"model:    {reviewer.model}", file=sys.stderr)
    if not key:
        print("api key:  (none found in env or .env)", file=sys.stderr)
        print("FAIL: no key available. Paste it into .env.", file=sys.stderr)
        return 1
    masked = key[:7] + "..." + key[-4:] if len(key) > 12 else "(short)"
    print(f"api key:  {masked}  (length={len(key)})", file=sys.stderr)

    probe = Path(__file__).parent / "__init__.py"
    findings = reviewer.analyze(probe)
    for f in findings:
        if f.rule_id == "LLM-ERR":
            print(f"FAIL: {f.detail}", file=sys.stderr)
            _hint_for_401(f.detail, reviewer.provider, key)
            return 1
        if f.rule_id == "LLM-CFG":
            print(f"FAIL: {f.detail}", file=sys.stderr)
            return 1
    print(f"OK: provider responded with {len(findings)} finding(s).",
          file=sys.stderr)
    return 0


def _hint_for_401(detail: str, provider: str, key: str) -> None:
    lower = detail.lower()
    if "401" in detail:
        print("", file=sys.stderr)
        print("401 = the provider rejected the key. Common causes:",
              file=sys.stderr)
        if provider == "openai":
            if key.startswith("sk-or-"):
                print("  * Your key starts with 'sk-or-' — that is an "
                      "OpenRouter key, not OpenAI.", file=sys.stderr)
                print("    Fix: run with --provider openrouter, or paste "
                      "an OpenAI key from", file=sys.stderr)
                print("    https://platform.openai.com/api-keys.",
                      file=sys.stderr)
                return
            if not key.startswith(("sk-", "sk-proj-")):
                print(f"  * Key prefix is {key[:6]!r}; OpenAI keys start "
                      "with 'sk-' or 'sk-proj-'.", file=sys.stderr)
        else:
            if not key.startswith("sk-or-"):
                print(f"  * Key prefix is {key[:6]!r}; OpenRouter keys "
                      "start with 'sk-or-'.", file=sys.stderr)
        print("  * Key may be revoked, expired, or from the wrong org. "
              "Regenerate it.", file=sys.stderr)
        print("  * Make sure .env has no surrounding quotes or trailing "
              "whitespace.", file=sys.stderr)
        return

    if "429" in detail or "too many requests" in lower or "quota" in lower:
        print("", file=sys.stderr)
        print("429 = the provider accepted the key but is throttling you. "
              "Likely causes:", file=sys.stderr)
        if provider == "openai":
            print("  * No billing set up on the OpenAI account. A "
                  "brand-new key returns 429 on every call until you add",
                  file=sys.stderr)
            print("    a payment method at "
                  "https://platform.openai.com/settings/organization/billing.",
                  file=sys.stderr)
            print("  * Monthly usage quota is exhausted — check "
                  "https://platform.openai.com/usage.", file=sys.stderr)
            print("  * Tier-0 rate limits (~3 req/min). The client now "
                  "retries with backoff, but large scans may still "
                  "exceed the quota.", file=sys.stderr)
            print("", file=sys.stderr)
            print("  Workaround: switch to OpenRouter (often has free "
                  "model credits):", file=sys.stderr)
            print("    1. Get a key at https://openrouter.ai/keys",
                  file=sys.stderr)
            print("    2. Add OPENROUTER_API_KEY=sk-or-... to .env",
                  file=sys.stderr)
            print("    3. Run with --provider openrouter",
                  file=sys.stderr)
        else:
            print("  * OpenRouter rate limit hit; wait a minute and "
                  "retry, or add credits at https://openrouter.ai/credits.",
                  file=sys.stderr)
        return


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
