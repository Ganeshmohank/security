# secscan - Project Summary

CMPE-279, two-person team.

## Problem statement

The course brief asks for a Python-based static analyser that detects
common security vulnerabilities (SQL injection, hardcoded credentials,
improper input validation, unsafe dynamic execution), uses libraries
like `ast`, `bandit`, and `radon`, and produces a report that could
plug into a CI pipeline. `secscan` answers that brief by combining an
in-house rule engine with three external analysis sources and
cross-validating the results.

## Design goals

1. Keep the shared contract between modules minimal. All detectors emit
   the same `Finding` dataclass, which lets each engine evolve
   independently.
2. Make each detection rule its own class. Adding a new rule should
   require editing one file and appending to a list, not rewriting a
   monolithic visitor.
3. Treat the LLM as one engine among four. It never blocks the scan,
   and the scanner still produces a useful report when the API key is
   absent.
4. Return a CI-friendly exit code when findings of a chosen severity
   are present. The brief explicitly mentions CI/CD feedback, and
   `--fail-on` is the minimum hook a pipeline needs.

## Architecture

```
     +--------+     +-----------------+     +----------------+
     |  CLI   | --> |  core/scanner   | --> |  report/builder|
     +--------+     +-----------------+     +----------------+
                            |
          +--------+--------+--------+--------+
          |        |        |        |
     +---------+ +--------+ +--------+ +--------+
     |  rules  | | bandit | | radon  | |  llm   |
     | (AST)   | | (proc) | | (lib)  | | (API)  |
     +---------+ +--------+ +--------+ +--------+
                     \     |     |     /
                      v    v    v    v
                  core/finding (dataclass)
```

`CodeScanner.scan(path)` walks the filesystem, hands each `.py` file to
every enabled engine, and aggregates results into a `ScanResult`. A
dedupe pass looks for findings reported by two or more engines on the
same rough line number and tags them as `confirmed`.

## Detection catalogue

### AST rules (in-house)

| Rule   | Title                              | Severity  | Notes                                                      |
|--------|------------------------------------|-----------|------------------------------------------------------------|
| SEC001 | Possible SQL injection             | high      | Direct + taint-lite (`sql = f"..."; execute(sql)`)         |
| SEC002 | Hardcoded secret                   | critical  | AST-level assignment detection + Shannon-entropy gate      |
| SEC003 | Dangerous call                     | high      | `eval`, `exec`, `pickle.loads`, `shell=True`, etc.         |
| SEC004 | Unvalidated input                  | medium    | `input()`, Flask `request.*`, `sys.argv` subscripts        |
| SEC005 | Weak cryptographic primitive       | medium    | `hashlib.md5`/`sha1`, `hashlib.new('md5')`                 |
| SEC006 | Insecure PRNG in security context  | medium    | `random.*` in files that mention tokens/passwords/etc.     |
| SEC007 | Insecure temporary file            | medium    | `tempfile.mktemp()`, `open("/tmp/...", "w")`               |

### Bandit subset

`B201` Flask debug, `B506` unsafe `yaml.load`, `B602` subprocess
`shell=True`, `B701` Jinja2 `autoescape=False`.

### Radon engine

The `RadonRunner` uses the `radon` library in-process to compute
cyclomatic complexity for every function/method. Grades map to
severities as follows:

| Grade | Complexity | Severity |
|-------|------------|----------|
| A / B | 1 - 10     | (ignored)|
| C     | 11 - 20    | low      |
| D     | 21 - 30    | medium   |
| E     | 31 - 40    | high     |
| F     | 41+        | critical |

Complexity is not itself a vulnerability, but it strongly correlates
with hard-to-audit code paths, so reviewers get a clear nudge toward
the functions most likely to hide bugs.

### LLM engine

OpenRouter chat completion in JSON object mode. The system prompt asks
for a strict `{"findings": [...]}` shape, which removes the need for
the fragile regex parsing of the previous implementation.

## Key implementation decisions

- `Finding` is a `@dataclass` with a `to_dict()` shim that keeps the
  older `type/message/description` keys alive for any downstream tool
  still consuming the JSON output.
- The cross-engine dedupe is string-normalised: rule IDs, titles, and
  the first sentence of the detail are lower-cased and mapped to a small
  set of canonical buckets (`sqli`, `secret`, `dangerous`, `debug`,
  `xss`, `crypto`). Line numbers are bucketed to pair ranges
  (`line // 2`) so an AST finding on line 12 and a bandit finding on
  line 13 still cluster.
- `HardcodedSecretRule` walks `Assign` / `AnnAssign` nodes rather than
  scanning raw text. This makes the rule immune to the classic false
  positive where the word `password=` appears *inside* an f-string SQL
  query; it also means typed assignments (`API_KEY: str = "..."`) are
  caught.
- `SqlInjectionRule` runs a first pass that records variables assigned
  to unsafe string expressions inside each function, then flags any
  `execute*` call that references one of those variables. It is a
  deliberately shallow taint table - scoped to the enclosing function,
  no cross-module tracking - but it fixes the most common real-world
  miss without pulling in a heavyweight dataflow framework.
- The entropy check in `HardcodedSecretRule` uses Shannon entropy
  >= 4.0 bits/char. This roughly matches observed entropy of real tokens
  while filtering out long but repetitive dictionary words.
- The HTML report uses a native `<details>` element for collapsible
  file sections so the output remains a single self-contained HTML file
  with zero JavaScript, safe to email or open offline.

## Team split

| Area                                                  | Owner       |
|-------------------------------------------------------|-------------|
| `secscan/core/finding.py` (shared contract)           | Both (A first) |
| `secscan/rules/ast_rules.py`, `tests/test_ast_rules.py`, `test_code/` | Teammate A |
| `secscan/engines/bandit_runner.py`                    | Teammate A  |
| `secscan/engines/radon_runner.py`, `tests/test_radon_runner.py` | Teammate A |
| `secscan/core/scanner.py`, `tests/test_scanner.py`    | Teammate B  |
| `secscan/engines/llm_client.py`                       | Teammate B  |
| `secscan/report/builder.py`, `tests/test_report_builder.py` | Teammate B  |
| `secscan/cli.py`, `cli.py`, docs                      | Teammate B  |

## Results on the bundled fixtures

`python cli.py test_code` on the fixture tree (five files) reports:

- Nine critical hardcoded secrets across `config.py`, `app.py`,
  `utils.py`, `database.py`.
- Ten high-severity findings (SQL injection via concatenation, f-string
  format, and the taint-lite pattern `sql = f"..."; cur.execute(sql)`
  in `database.py`; `eval()` / `exec()` / `pickle.loads()` /
  `yaml.load()` / `subprocess.Popen(..., shell=True)` in `utils.py`
  and `app.py`).
- Ten medium-severity findings covering unvalidated input, weak crypto
  (`md5`, `sha1`), insecure PRNG for session tokens in `utils.py`, and
  insecure tempfile usage in `utils.py`.
- One radon complexity finding on `route_template` in `templates.py`.
- Two bandit `B602` shell-injection findings on `utils.py` that cluster
  with the AST `SEC003` findings to produce two `confirmed` entries.

Adding `--llm` on top typically produces additional confirmed findings
because the model agrees with the AST rules on the obvious credential
and SQL injection sites.

## Testing

`pytest` suite covers:

- One or more tests per AST rule (true-positive and true-negative
  branches), including the taint-lite SQLi cases and the fix that
  keeps the secret rule from firing inside f-strings.
- Radon runner: low-complexity code is silent, branchy code is flagged,
  `--radon-min-grade F` suppresses everything but the worst offenders,
  syntax errors surface as an informational finding.
- Scanner behaviour: single file, directory walk, `__pycache__`
  skipping, JSON round-trip, cross-engine confirmation via the private
  helper.
- Report builder: text badges, JSON shape, HTML severity classes,
  per-file badges, collapsible `<details>` sections, render-dispatch
  fallback.

```
$ python -m pytest tests/ -q
..........................................................
58 passed in 0.23s
```

## Limitations and future work

- Taint tracking is intentionally shallow. It catches the two-statement
  pattern inside a single function but does not follow values across
  function calls or modules.
- Bandit is invoked as a subprocess; running it inside the host Python
  process via its library API would be faster for large trees.
- Radon only measures cyclomatic complexity. `radon mi` (maintainability
  index) and `radon hal` (Halstead metrics) would be easy follow-ups.
- Only Python is supported.
- The CI example in the README is a starting point; a dedicated GitHub
  Actions workflow and SARIF uploader would be natural next steps
  (explicitly deferred as out-of-scope for this revision).
