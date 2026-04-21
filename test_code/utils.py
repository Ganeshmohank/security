"""Vulnerable utility helpers (fixture)."""

import pickle
import random
import subprocess
import tempfile

import yaml


PROVIDER_API_KEY = "sk-proj-abc123xyz7890"


def launch_echo(payload):
    subprocess.Popen(f"/bin/echo {payload}", shell=True)
    return "ok"


def parse_config(cfg_path):
    with open(cfg_path, "r") as fh:
        return yaml.load(fh)


def revive(blob):
    return pickle.loads(blob)


def read_user():
    raw = input("Enter your data: ")
    return _dispatch(raw)


def make_session_token():
    # Insecure PRNG for a security-sensitive token.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(16))


def cache_upload(buf):
    path = tempfile.mktemp()
    with open("/tmp/secscan_cache.bin", "w") as fh:
        fh.write(buf)
    return path


def _dispatch(expr):
    exec(f"result = {expr}")
    return result  # noqa: F821 - deliberately broken
