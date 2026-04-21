"""Pytest fixtures for secscan tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


@pytest.fixture()
def snippet(tmp_path: Path):
    """Write a code snippet to a temp .py file and return its Path."""
    counter = {"n": 0}

    def _make(code: str, name: str | None = None) -> Path:
        counter["n"] += 1
        filename = name or f"sample_{counter['n']}.py"
        target = tmp_path / filename
        target.write_text(code, encoding="utf-8")
        return target

    return _make


@pytest.fixture()
def parsed():
    """Return (tree, source) from a raw code string."""

    def _parse(code: str):
        return ast.parse(code), code

    return _parse
