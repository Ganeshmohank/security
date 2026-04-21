# secscan

A lightweight static analyzer for Python source that looks for a focused set
of security defects: SQL injection (with lightweight taint tracking),
hardcoded credentials, unsafe code-execution primitives, missing input
validation, weak cryptographic hashes, predictable PRNG in security-sensitive
code, and insecure temporary files. Results from four independent engines
are cross-checked so that any finding reported by more than one engine is
highlighted as "confirmed".

This repository is the CMPE-279 project deliverable.

---

## Why four engines

| Engine   | Type                     | What it is good at                                           |
| -------- | ------------------------ | ------------------------------------------------------------ |
| `ast`    | rule registry in-house   | Custom rules with fast, deterministic checks                 |
| `bandit` | shells out to `bandit`   | Mature, opinionated ruleset from the wider community         |
| `radon`  | in-process `radon` lib   | Cyclomatic-complexity hotspots that reviewers should re-read |
| `llm`    | OpenRouter chat endpoint | Context-aware review, catches patterns the rules miss        |

The `ast` engine is always on. `bandit` and `radon` run by default when
their packages are installed. The `llm` engine is opt-in with `--llm` and
requires `OPENROUTER_API_KEY` to be present.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you intend to run the LLM engine:

```bash
export OPENROUTER_API_KEY="sk-or-..."
```

## Usage

The repository ships both a top-level shim (`cli.py`) and the packaged
entry point (`python -m secscan.cli`). Both accept the same flags.

Scan a file or a directory:

```bash
python cli.py example_vulnerable_code.py
python cli.py test_code
```

Flags:

| Flag                     | Purpose                                                       |
| ------------------------ | ------------------------------------------------------------- |
| `--no-bandit`            | Skip the bandit engine                                        |
| `--no-radon`             | Skip the radon complexity engine                              |
| `--radon-min-grade G`    | Lowest radon grade that produces a finding (A-F, default `C`) |
| `--llm`                  | Enable LLM review (needs `OPENROUTER_API_KEY`)                |
| `--model MODEL`          | OpenRouter model id (default `deepseek/deepseek-chat`)        |
| `-o, --output PATH`      | Write report to a file instead of stdout                      |
| `-f, --format FMT`       | `text`, `json`, or `html` (default `text`)                    |
| `--min-severity LVL`     | Hide findings below LVL (`low`, `medium`, `high`, `critical`) |
| `--fail-on LVL`          | Exit non-zero when any finding at or above LVL is present     |

Example that generates an HTML report and fails the shell pipeline on any
high-or-above finding:

```bash
python cli.py test_code -f html -o report.html --fail-on high
```

## What the tool looks for

Seven AST rules plus a curated subset of bandit tests and radon complexity
grading:

| Rule ID | Title                              | Engine | Severity       |
| ------- | ---------------------------------- | ------ | -------------- |
| SEC001  | SQL injection (taint-lite)         | ast    | high           |
| SEC002  | Hardcoded secret (regex + entropy) | ast    | critical       |
| SEC003  | Dangerous call                     | ast    | high           |
| SEC004  | Unvalidated input                  | ast    | medium         |
| SEC005  | Weak cryptographic primitive       | ast    | medium         |
| SEC006  | Insecure PRNG in security context  | ast    | medium         |
| SEC007  | Insecure temporary file            | ast    | medium         |
| B201    | Flask debug mode                   | bandit | high           |
| B506    | Unsafe `yaml.load`                 | bandit | medium         |
| B602    | Subprocess with `shell=True`       | bandit | high           |
| B701    | Jinja2 `autoescape=False`          | bandit | high           |
| CC-C..F | Cyclomatic-complexity hotspot      | radon  | low - critical |

Notable details:

- **SEC001** fires on `execute()` arguments built with f-strings,
  `%`-formatting, `.format()`, or `+`-concatenation, *and* on the common
  two-statement pattern `sql = f"..."; cur.execute(sql)` via a lightweight
  intra-function taint table.
- **SEC002** uses AST-level assignment detection instead of raw regex, so
  it never false-positives on keyword-shaped text that happens to appear
  inside an f-string SQL query.
- **SEC006** only fires in files that mention security-sensitive terms
  (token, secret, password, nonce, salt, session, otp, api key, csrf) to
  keep signal-to-noise high.
- **CC-x** uses radon's letter grades: `C` (11-20) and below are skipped
  by default; `D`/`E`/`F` escalate to medium/high/critical.

## Reports

All three output formats carry the same information, but the HTML report
is tuned for demos and review sessions:

- Global severity bar (critical / high / medium / low / info counts).
- Per-file badges showing how each severity breaks down.
- Native `<details>` collapsible file sections (no JavaScript).
- A 3-line source snippet around every finding, with the offending line
  highlighted.

## Project layout

```
secscan/
    core/
        finding.py        dataclass returned by every engine
        scanner.py        orchestration + cross-engine dedupe
    rules/
        ast_rules.py      rule registry (SEC001..SEC007)
    engines/
        bandit_runner.py  subprocess wrapper around `bandit`
        radon_runner.py   in-process radon complexity engine
        llm_client.py     OpenRouter reviewer (JSON response mode)
    report/
        builder.py        text / JSON / HTML renderers
    cli.py                argparse CLI entry point
cli.py                    root-level shim
tests/                    pytest suite (rules, scanner, radon, reports)
test_code/                deliberately vulnerable fixtures
example_vulnerable_code.py  single-file showcase
```

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -q
```

The suite currently has 58 tests covering every AST rule (true positives
and true negatives), the taint-lite SQLi logic, the radon engine with
grade thresholds, scanner orchestration and cross-engine dedupe, and the
text / JSON / HTML report renderers.

## Team split

The codebase is designed around a single shared contract (`core/finding.py`)
so the two teammates can work in parallel with minimal merge friction:

- Teammate A owns `secscan/rules/`, `secscan/engines/bandit_runner.py`,
  `secscan/engines/radon_runner.py`, `test_code/` fixtures, and
  `tests/test_ast_rules.py` + `tests/test_radon_runner.py`.
- Teammate B owns `secscan/core/scanner.py`, `secscan/engines/llm_client.py`,
  `secscan/report/`, `secscan/cli.py`, `tests/test_scanner.py`,
  `tests/test_report_builder.py`, and the docs.

## Known limits

- Python source only.
- Taint tracking is intentionally shallow: it tracks unsafe string
  assignments within a single function scope but does not follow values
  across calls.
- `bandit` and `radon` must be installed. When either is missing, the
  scan still completes with an informational finding noting the skip.
- LLM review depends on a third-party API, so results can vary between
  runs.

## CI wiring (suggested)

The `--fail-on` flag is enough to gate a GitHub Actions job:

```yaml
- run: pip install -r requirements.txt
- run: python cli.py path/to/src --fail-on high
```
