"""AST-driven vulnerability rules.

This module replaces the old monolithic ``ASTSecurityAnalyzer``. Each check
is expressed as a separate ``Rule`` subclass that is registered in the
``RULES`` list. A rule walks the tree (or raw text, for the regex-based
secret rule) and appends ``Finding`` objects to a shared buffer.

Adding a new rule is intentionally cheap: subclass ``Rule``, implement
``check``, and append the class name to ``RULES``.
"""

from __future__ import annotations

import ast
import math
import re
from pathlib import Path
from typing import Iterable, List, Sequence

from ..core.finding import Finding


# ---------------------------------------------------------------------------
# Rule base + helpers
# ---------------------------------------------------------------------------


class Rule:
    """Base class for every AST-level rule.

    Rules receive the parsed ``tree`` plus the raw ``source`` text so that
    regex-style checks do not have to re-read the file from disk.
    """

    rule_id: str = "R000"
    title: str = "Generic issue"
    severity: str = "medium"

    def check(self, tree: ast.AST, source: str, path: Path) -> Iterable[Finding]:
        raise NotImplementedError

    def _finding(self, path: Path, line: int, detail: str, title: str | None = None) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            severity=self.severity,
            file=str(path),
            line=line,
            detail=detail,
            engine="ast",
        )


def _shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character. Used to filter dictionary-like
    strings out of the generic high-entropy secret check."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _attr_chain(node: ast.AST) -> str:
    """Best-effort dotted path for an ``Attribute``/``Name`` node
    (e.g. ``hashlib.md5`` or ``subprocess.Popen``). Returns "" when the
    expression is more complex than a simple chain."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


# ---------------------------------------------------------------------------
# Rule 1 - SQL injection (extended)
# ---------------------------------------------------------------------------


SQL_EXECUTE_METHODS = {"execute", "executemany", "executescript"}


class SqlInjectionRule(Rule):
    """Flag dynamic string composition reaching a SQL ``execute*`` call.

    Detects three flavours:

    1. Direct: ``cur.execute(f"...")`` / ``.format()`` / ``%`` / ``+``.
    2. Taint-lite: ``sql = f"..."; cur.execute(sql)`` where the name was
       assigned an unsafe expression in the same function scope.
    3. Same but via ``+=`` append.
    """

    rule_id = "SEC001"
    title = "Possible SQL injection"
    severity = "high"

    def check(self, tree, source, path):
        findings: list[Finding] = []
        tainted = _collect_tainted_names(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr not in SQL_EXECUTE_METHODS:
                continue
            if not node.args:
                continue

            arg = node.args[0]
            reason = self._classify_risk(arg)

            if reason is None and isinstance(arg, ast.Name) and arg.id in tainted:
                reason = f"a tainted variable {arg.id!r} (assigned {tainted[arg.id]})"

            if reason is None:
                continue

            findings.append(
                self._finding(
                    path,
                    node.lineno,
                    f"SQL query built via {reason}. Use parameterised queries "
                    "(cursor.execute(sql, params)) instead of string composition.",
                )
            )
        return findings

    @staticmethod
    def _classify_risk(arg: ast.AST) -> str | None:
        if isinstance(arg, ast.JoinedStr):
            return "an f-string"
        if isinstance(arg, ast.BinOp):
            if isinstance(arg.op, ast.Mod):
                return "%-formatting"
            if isinstance(arg.op, ast.Add):
                return "string concatenation"
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
            if arg.func.attr == "format":
                return ".format()"
        return None


def _collect_tainted_names(tree: ast.AST) -> dict[str, str]:
    """Return ``{name: reason}`` for variables assigned an unsafe string."""
    tainted: dict[str, str] = {}

    def _label(value: ast.AST) -> str | None:
        if isinstance(value, ast.JoinedStr):
            return "from an f-string"
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
            return "from %-formatting"
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            return "from string concatenation"
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "format"
        ):
            return "from .format()"
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node.value is not None:
            label = _label(node.value)
            if label is None:
                continue
            for tgt in node.targets:
                name = _target_name(tgt)
                if name:
                    tainted[name] = label
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            name = _target_name(node.target)
            if name:
                tainted.setdefault(name, "from +=/ concatenation")
    return tainted


# ---------------------------------------------------------------------------
# Rule 2 - Hardcoded secrets (regex + entropy)
# ---------------------------------------------------------------------------


# Names that, when used as the left-hand side of an assignment to a bare
# string literal, are almost certainly storing a credential.
_SECRET_NAME = re.compile(
    r"(?i)(?:"
    r"pass(?:word|wd)?|"
    r"api[_-]?key|"
    r"secret(?:[_-]?key)?|"
    r"token|bearer|"
    r"client[_-]?secret|"
    r"private[_-]?key|"
    r"aws[_-]?access[_-]?key(?:[_-]?id)?|"
    r"aws[_-]?secret[_-]?(?:access[_-]?)?key|"
    r"encryption[_-]?key|"
    r"jwt[_-]?secret"
    r")\b"
)

# Charset for generic high-entropy literals (base64/hex/token-ish).
_GENERIC_CHARSET = re.compile(r"^[A-Za-z0-9/+=_\-]{32,}$")


class HardcodedSecretRule(Rule):
    """Flag string literals stored on variables whose name looks like a
    credential, and any top-level constant holding a high-entropy string.

    Switched to AST-based detection so matches never fire *inside* f-strings
    or other dynamic string expressions (a common false-positive source).
    """

    rule_id = "SEC002"
    title = "Hardcoded secret"
    severity = "critical"

    def check(self, tree, source, path):
        findings: list[Finding] = []

        for node in ast.walk(tree):
            targets: list[ast.AST] = []
            value: ast.AST | None = None

            if isinstance(node, ast.Assign):
                targets = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
                value = node.value
            else:
                continue

            literal = _string_constant(value)
            if literal is None:
                continue

            for tgt in targets:
                name = _target_name(tgt)
                if not name:
                    continue

                if _SECRET_NAME.search(name):
                    findings.append(
                        self._finding(
                            path,
                            node.lineno,
                            f"Credential literal in source: {name} = "
                            f"{literal[:48]!r}. Move secrets to environment "
                            "variables or a secrets manager.",
                        )
                    )
                    break

                if (
                    len(literal) >= 32
                    and _GENERIC_CHARSET.match(literal)
                    and _shannon_entropy(literal) >= 4.0
                ):
                    findings.append(
                        self._finding(
                            path,
                            node.lineno,
                            f"High-entropy literal assigned to {name!r}: "
                            f"{literal[:24]!s}... Looks like a secret; "
                            "move it out of version control.",
                            title="Hardcoded secret (entropy)",
                        )
                    )
                    break
        return findings


def _string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


# ---------------------------------------------------------------------------
# Rule 3 - Dangerous function calls (extended)
# ---------------------------------------------------------------------------


# qualified_name -> human label
_DANGEROUS_CALLS: dict[str, str] = {
    "eval": "eval()",
    "exec": "exec()",
    "pickle.loads": "pickle.loads()",
    "pickle.load": "pickle.load()",
    "marshal.loads": "marshal.loads()",
    "yaml.load": "yaml.load() without SafeLoader",
    "os.system": "os.system()",
}


class DangerousCallRule(Rule):
    rule_id = "SEC003"
    title = "Dangerous function call"
    severity = "high"

    def check(self, tree, source, path):
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Simple name calls: eval(...), exec(...)
            if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_CALLS:
                label = _DANGEROUS_CALLS[node.func.id]
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        f"{label} executes arbitrary code. Replace with a parser, "
                        "a dispatch table, or ast.literal_eval().",
                    )
                )
                continue

            # Dotted calls: pickle.loads(...), subprocess.Popen(..., shell=True)
            dotted = _attr_chain(node.func)
            if dotted in _DANGEROUS_CALLS:
                label = _DANGEROUS_CALLS[dotted]
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        f"{label} is unsafe on untrusted input.",
                    )
                )
                continue

            # shell=True on any subprocess.* helper
            if dotted.startswith("subprocess.") and _has_kwarg_true(node, "shell"):
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        f"{dotted}(..., shell=True) enables shell expansion. "
                        "Pass an argument list and drop shell=True.",
                    )
                )

            # requests.* with verify=False
            if dotted.startswith("requests.") and _has_kwarg_false(node, "verify"):
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        f"{dotted}(..., verify=False) disables TLS verification.",
                        title="Insecure TLS",
                    )
                )
        return findings


def _has_kwarg_true(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _has_kwarg_false(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule 4 - Unvalidated input
# ---------------------------------------------------------------------------


class UnvalidatedInputRule(Rule):
    rule_id = "SEC004"
    title = "Unvalidated input"
    severity = "medium"

    _BARE_INPUT_FUNCS = {"input", "raw_input"}
    _REQUEST_ATTRS = {"form", "args", "values", "json", "get_json", "cookies", "headers"}

    def check(self, tree, source, path):
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # input() / raw_input()
            if isinstance(node.func, ast.Name) and node.func.id in self._BARE_INPUT_FUNCS:
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        f"{node.func.id}() returns unvalidated user data. "
                        "Validate and whitelist before use.",
                    )
                )
                continue

            # request.args.get(...), request.form.get(...), etc.
            dotted = _attr_chain(node.func)
            if dotted.startswith("request."):
                tail = dotted.split(".")[1] if "." in dotted[len("request.") :] else ""
                if tail in self._REQUEST_ATTRS:
                    findings.append(
                        self._finding(
                            path,
                            node.lineno,
                            f"{dotted}(...) is user-controlled. "
                            "Apply schema validation (e.g. pydantic, WTForms) before use.",
                        )
                    )

        # sys.argv[...] subscripts
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and _attr_chain(node.value) == "sys.argv":
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        "sys.argv access reaches user input. Validate before "
                        "passing to subprocess/database/filesystem sinks.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Rule 5 - Weak cryptography (new)
# ---------------------------------------------------------------------------


_WEAK_HASHES = {"md5", "sha1"}


class WeakCryptoRule(Rule):
    rule_id = "SEC005"
    title = "Weak cryptographic primitive"
    severity = "medium"

    def check(self, tree, source, path):
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _attr_chain(node.func)

            # hashlib.md5(...) / hashlib.sha1(...)
            if dotted in {f"hashlib.{h}" for h in _WEAK_HASHES}:
                algo = dotted.split(".")[-1].upper()
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        f"{algo} is cryptographically broken. Use hashlib.sha256() or "
                        "argon2/bcrypt/scrypt for passwords.",
                    )
                )
                continue

            # hashlib.new("md5") / hashlib.new("sha1")
            if dotted == "hashlib.new" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    if first.value.lower() in _WEAK_HASHES:
                        findings.append(
                            self._finding(
                                path,
                                node.lineno,
                                f"hashlib.new('{first.value}') selects a broken algorithm.",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# Registry + entry point
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Rule 6 - Insecure PRNG in security-looking contexts (new)
# ---------------------------------------------------------------------------


_WEAK_RANDOM_FUNCS = {
    "random", "randint", "randrange", "choice", "choices",
    "sample", "uniform", "getrandbits", "shuffle",
}

_SECURITY_HINTS = re.compile(
    r"(?i)\b(token|secret|password|passwd|nonce|salt|session|otp|api[_-]?key|csrf)\b"
)


class WeakRandomRule(Rule):
    """``random.*`` used in a file whose source mentions tokens/secrets/etc.

    This is heuristic: we never know for sure whether a value is
    security-sensitive, but in practice a file that mentions ``token`` or
    ``password`` should reach for ``secrets`` instead of ``random``.
    """

    rule_id = "SEC006"
    title = "Insecure PRNG in security context"
    severity = "medium"

    def check(self, tree, source, path):
        if not _SECURITY_HINTS.search(source):
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _attr_chain(node.func)
            if not dotted.startswith("random."):
                continue
            func_name = dotted.split(".", 1)[1]
            if func_name not in _WEAK_RANDOM_FUNCS:
                continue
            findings.append(
                self._finding(
                    path,
                    node.lineno,
                    f"{dotted}(...) uses Python's predictable PRNG. In a file "
                    "that handles tokens/secrets/passwords use the `secrets` "
                    "module (e.g. secrets.token_urlsafe()).",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Rule 7 - Insecure temporary files (new)
# ---------------------------------------------------------------------------


_WORLD_WRITABLE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


class InsecureTempFileRule(Rule):
    """``tempfile.mktemp()`` and ``open("/tmp/...", "w")`` patterns."""

    rule_id = "SEC007"
    title = "Insecure temporary file"
    severity = "medium"

    def check(self, tree, source, path):
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _attr_chain(node.func)

            if dotted == "tempfile.mktemp":
                findings.append(
                    self._finding(
                        path,
                        node.lineno,
                        "tempfile.mktemp() is race-prone. Use "
                        "tempfile.NamedTemporaryFile or mkstemp().",
                    )
                )
                continue

            # open("/tmp/something", "w") / open("/tmp/..", mode="w")
            is_open = (
                (isinstance(node.func, ast.Name) and node.func.id == "open")
                or dotted == "os.open"
            )
            if not is_open or not node.args:
                continue
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            if not first.value.startswith(_WORLD_WRITABLE_PREFIXES):
                continue
            if not _open_is_write(node):
                continue
            findings.append(
                self._finding(
                    path,
                    node.lineno,
                    f"open({first.value!r}, write) writes to a world-writable "
                    "directory with a predictable name. Use tempfile.mkstemp().",
                )
            )
        return findings


def _open_is_write(call: ast.Call) -> bool:
    """Best-effort: is this ``open()`` being used for writing?"""
    # Positional mode
    if len(call.args) >= 2:
        mode = call.args[1]
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
            return any(ch in mode.value for ch in "wax+")
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return any(ch in str(kw.value.value) for ch in "wax+")
    # open() with no mode defaults to 'r'; treat default as safe.
    return False


RULES: list[type[Rule]] = [
    SqlInjectionRule,
    HardcodedSecretRule,
    DangerousCallRule,
    UnvalidatedInputRule,
    WeakCryptoRule,
    WeakRandomRule,
    InsecureTempFileRule,
]


def run_rules(path: Path) -> List[Finding]:
    """Parse ``path`` and run every registered rule against it."""
    try:
        source = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return [
            Finding(
                rule_id="SEC000",
                title="Read error",
                severity="error",
                file=str(path),
                line=0,
                detail=f"Could not read file: {exc}",
                engine="ast",
            )
        ]

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [
            Finding(
                rule_id="SEC000",
                title="Syntax error",
                severity="info",
                file=str(path),
                line=exc.lineno or 0,
                detail=f"{exc.msg}",
                engine="ast",
            )
        ]

    out: list[Finding] = []
    for rule_cls in RULES:
        rule = rule_cls()
        try:
            out.extend(rule.check(tree, source, Path(path)))
        except Exception as exc:  # don't let one bad rule kill the scan
            out.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=f"Rule error in {rule_cls.__name__}",
                    severity="error",
                    file=str(path),
                    line=0,
                    detail=str(exc),
                    engine="ast",
                )
            )
    return out
