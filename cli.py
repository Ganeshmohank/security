#!/usr/bin/env python3
"""Shim that forwards to ``python -m secscan.cli``.

Kept at the repo root so legacy commands like ``python cli.py file.py``
continue to work.
"""

from secscan.cli import run


if __name__ == "__main__":
    import sys
    sys.exit(run())
