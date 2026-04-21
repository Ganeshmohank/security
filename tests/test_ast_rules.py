"""Unit tests for each AST rule in ``secscan.rules.ast_rules``."""

from __future__ import annotations

from pathlib import Path

from secscan.rules.ast_rules import (
    DangerousCallRule,
    HardcodedSecretRule,
    InsecureTempFileRule,
    SqlInjectionRule,
    UnvalidatedInputRule,
    WeakCryptoRule,
    WeakRandomRule,
    run_rules,
)


PATH = Path("sample.py")


def _run(rule, code: str):
    import ast as _ast

    return list(rule.check(_ast.parse(code), code, PATH))


# ---------------------------------------------------------------------------
# SqlInjectionRule
# ---------------------------------------------------------------------------


def test_sqli_flags_fstring():
    code = "cur.execute(f\"SELECT * FROM t WHERE id={x}\")"
    hits = _run(SqlInjectionRule(), code)
    assert len(hits) == 1
    assert "f-string" in hits[0].detail


def test_sqli_flags_percent_formatting():
    code = 'cur.execute("SELECT * FROM t WHERE id=%s" % uid)'
    assert len(_run(SqlInjectionRule(), code)) == 1


def test_sqli_flags_concatenation():
    code = 'cur.execute("SELECT * FROM t WHERE name=\'" + name + "\'")'
    assert len(_run(SqlInjectionRule(), code)) == 1


def test_sqli_flags_format_method():
    code = 'cur.execute("SELECT * FROM t WHERE id={}".format(uid))'
    assert len(_run(SqlInjectionRule(), code)) == 1


def test_sqli_skips_parameterised_query():
    code = 'cur.execute("SELECT * FROM t WHERE id=?", (uid,))'
    assert _run(SqlInjectionRule(), code) == []


def test_sqli_covers_executescript():
    code = "cur.executescript(f\"DROP TABLE {name}\")"
    assert len(_run(SqlInjectionRule(), code)) == 1


def test_sqli_taint_lite_assigned_fstring():
    code = (
        "def q(x):\n"
        "    sql = f\"SELECT * FROM t WHERE id={x}\"\n"
        "    cur.execute(sql)\n"
    )
    hits = _run(SqlInjectionRule(), code)
    assert any("tainted" in h.detail for h in hits)


def test_sqli_taint_lite_assigned_format():
    code = (
        "def q(x):\n"
        "    sql = 'SELECT * FROM t WHERE id={}'.format(x)\n"
        "    cur.execute(sql)\n"
    )
    assert len(_run(SqlInjectionRule(), code)) == 1


def test_sqli_taint_lite_assigned_percent():
    code = (
        "def q(x):\n"
        "    sql = 'SELECT * FROM t WHERE id=%s' % x\n"
        "    cur.execute(sql)\n"
    )
    assert len(_run(SqlInjectionRule(), code)) == 1


def test_sqli_taint_lite_ignores_literal_assignment():
    code = (
        "def q():\n"
        "    sql = 'SELECT 1'\n"
        "    cur.execute(sql)\n"
    )
    assert _run(SqlInjectionRule(), code) == []


# ---------------------------------------------------------------------------
# HardcodedSecretRule
# ---------------------------------------------------------------------------


def test_secret_rule_hits_obvious_assignment():
    code = 'API_KEY = "sk-aaaabbbbccccdddd"\n'
    hits = _run(HardcodedSecretRule(), code)
    assert any("Credential" in h.detail for h in hits)


def test_secret_rule_detects_aws_keys():
    code = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
    assert len(_run(HardcodedSecretRule(), code)) >= 1


def test_secret_rule_skips_comments():
    code = '# password = "do-not-flag"\n'
    assert _run(HardcodedSecretRule(), code) == []


def test_secret_rule_skips_fstring_sql_query():
    # Regression: `password = '{raw}'` inside an f-string used to fire a
    # false positive under the old regex-only implementation.
    code = (
        "def q(raw):\n"
        "    return f\"SELECT * FROM u WHERE password = '{raw}'\"\n"
    )
    assert _run(HardcodedSecretRule(), code) == []


def test_secret_rule_entropy_gate_rejects_dictionary_string():
    code = 'thing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
    assert _run(HardcodedSecretRule(), code) == []


def test_secret_rule_entropy_gate_accepts_high_entropy():
    code = 'thing = "xR39kLp7Zq2WvbM1oNs5tUy8aHcDfGeJ"\n'
    assert len(_run(HardcodedSecretRule(), code)) >= 1


def test_secret_rule_respects_typed_assignment():
    code = 'API_KEY: str = "sk-aaaabbbbccccddddeeeefff"\n'
    assert len(_run(HardcodedSecretRule(), code)) >= 1


# ---------------------------------------------------------------------------
# DangerousCallRule
# ---------------------------------------------------------------------------


def test_dangerous_eval():
    assert len(_run(DangerousCallRule(), "eval(x)")) == 1


def test_dangerous_exec():
    assert len(_run(DangerousCallRule(), "exec(x)")) == 1


def test_dangerous_pickle_loads():
    code = "import pickle\npickle.loads(blob)\n"
    assert len(_run(DangerousCallRule(), code)) == 1


def test_dangerous_subprocess_shell_true():
    code = "import subprocess\nsubprocess.Popen('ls', shell=True)\n"
    assert len(_run(DangerousCallRule(), code)) == 1


def test_dangerous_requests_verify_false():
    code = "import requests\nrequests.get('https://x', verify=False)\n"
    hits = _run(DangerousCallRule(), code)
    assert any("TLS" in h.title for h in hits)


def test_dangerous_skips_safe_code():
    code = "x = sum([1, 2, 3])\n"
    assert _run(DangerousCallRule(), code) == []


# ---------------------------------------------------------------------------
# UnvalidatedInputRule
# ---------------------------------------------------------------------------


def test_input_rule_hits_input_call():
    assert len(_run(UnvalidatedInputRule(), "x = input('hi')")) == 1


def test_input_rule_hits_flask_request_args():
    code = "from flask import request\nx = request.args.get('q')\n"
    assert len(_run(UnvalidatedInputRule(), code)) == 1


def test_input_rule_hits_sys_argv():
    code = "import sys\nx = sys.argv[1]\n"
    assert len(_run(UnvalidatedInputRule(), code)) == 1


def test_input_rule_ignores_other_calls():
    assert _run(UnvalidatedInputRule(), "x = len('hi')") == []


# ---------------------------------------------------------------------------
# WeakCryptoRule
# ---------------------------------------------------------------------------


def test_weakcrypto_hashlib_md5():
    code = "import hashlib\nhashlib.md5(b'x')"
    hits = _run(WeakCryptoRule(), code)
    assert len(hits) == 1
    assert "MD5" in hits[0].detail


def test_weakcrypto_hashlib_sha1():
    code = "import hashlib\nhashlib.sha1(b'x')"
    assert len(_run(WeakCryptoRule(), code)) == 1


def test_weakcrypto_hashlib_new_md5_literal():
    code = "import hashlib\nhashlib.new('md5')"
    assert len(_run(WeakCryptoRule(), code)) == 1


def test_weakcrypto_ignores_sha256():
    code = "import hashlib\nhashlib.sha256(b'x')"
    assert _run(WeakCryptoRule(), code) == []


# ---------------------------------------------------------------------------
# run_rules end-to-end
# ---------------------------------------------------------------------------


def test_run_rules_on_syntax_error(snippet):
    path = snippet("def :\n")
    findings = run_rules(path)
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].title == "Syntax error"


def test_run_rules_returns_multiple_rule_types(snippet):
    path = snippet(
        "import hashlib\n"
        "API_KEY = 'sk-aaaabbbbccccddddeeff'\n"
        "def f(x):\n"
        "    eval(x)\n"
        "    hashlib.md5(b'x')\n"
    )
    findings = run_rules(path)
    rule_ids = {f.rule_id for f in findings}
    assert {"SEC002", "SEC003", "SEC005"}.issubset(rule_ids)


# ---------------------------------------------------------------------------
# WeakRandomRule
# ---------------------------------------------------------------------------


def test_weakrandom_fires_when_file_mentions_tokens():
    code = (
        "import random\n"
        "# generate session token for user\n"
        "def make():\n"
        "    return random.choice(alphabet)\n"
    )
    hits = _run(WeakRandomRule(), code)
    assert len(hits) == 1
    assert "secrets" in hits[0].detail


def test_weakrandom_ignores_files_without_security_hints():
    code = (
        "import random\n"
        "def roll():\n"
        "    return random.randint(1, 6)\n"
    )
    assert _run(WeakRandomRule(), code) == []


def test_weakrandom_ignores_secrets_module():
    code = (
        "import secrets\n"
        "def token():\n"
        "    return secrets.token_urlsafe()\n"
    )
    assert _run(WeakRandomRule(), code) == []


# ---------------------------------------------------------------------------
# InsecureTempFileRule
# ---------------------------------------------------------------------------


def test_tempfile_mktemp_is_flagged():
    code = "import tempfile\np = tempfile.mktemp()\n"
    hits = _run(InsecureTempFileRule(), code)
    assert len(hits) == 1
    assert "mktemp" in hits[0].detail


def test_open_tmp_write_is_flagged():
    code = "open('/tmp/out.txt', 'w').write('x')\n"
    assert len(_run(InsecureTempFileRule(), code)) == 1


def test_open_tmp_read_is_safe():
    code = "open('/tmp/in.txt', 'r').read()\n"
    assert _run(InsecureTempFileRule(), code) == []


def test_open_non_tmp_write_is_safe():
    code = "open('./out.txt', 'w').write('x')\n"
    assert _run(InsecureTempFileRule(), code) == []
