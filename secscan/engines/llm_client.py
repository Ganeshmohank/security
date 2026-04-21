"""OpenRouter-backed code reviewer.

This engine is optional. When an API key is not configured, it returns a
single informational finding rather than raising, so the rest of the scan
keeps working. Responses are requested in JSON object mode, which removes
the fragile regex parser that the previous implementation used.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from ..core.finding import Finding


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

_SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. "
    "Inspect the provided Python source and list security issues only. "
    "Respond with a JSON object shaped like "
    '{"findings":[{"title":str,"severity":"low|medium|high|critical",'
    '"line":int,"detail":str}]}. '
    "If there are no issues, return {\"findings\": []}."
)

_MAX_SOURCE_CHARS = 8000


class LlmReviewer:
    """Thin OpenRouter wrapper for LLM-assisted review."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "deepseek/deepseek-chat",
        timeout: int = 60,
    ) -> None:
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model
        self.timeout = timeout

    def analyze(self, file_path: Path) -> List[Finding]:
        if not self.api_key:
            return [
                Finding(
                    rule_id="LLM-CFG",
                    title="LLM analysis skipped",
                    severity="info",
                    file=str(file_path),
                    line=0,
                    detail="Set OPENROUTER_API_KEY to enable LLM review.",
                    engine="llm",
                )
            ]

        try:
            source = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            return [self._error(file_path, f"Cannot read file: {exc}")]

        snippet = source if len(source) <= _MAX_SOURCE_CHARS else source[:_MAX_SOURCE_CHARS] + "\n# ...truncated..."

        try:
            raw = self._call(snippet)
        except Exception as exc:
            return [self._error(file_path, f"OpenRouter call failed: {exc}")]

        return self._decode(raw, file_path)

    # ------------------------------------------------------------------

    def _call(self, source: str) -> str:
        try:
            import requests
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("requests is required for LLM analysis") from exc

        body = {
            "model": self.model,
            "temperature": 0.1,
            "max_tokens": 1500,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Analyse this Python file and return the JSON object "
                        "described in the system prompt:\n\n"
                        f"```python\n{source}\n```"
                    ),
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-Title": "secscan",
            "HTTP-Referer": "https://github.com/",
        }
        resp = requests.post(OPENROUTER_URL, headers=headers,
                              data=json.dumps(body), timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _decode(self, raw: str, file_path: Path) -> List[Finding]:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            # Some providers wrap JSON in code fences despite response_format.
            cleaned = raw.strip().strip("`")
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
            try:
                payload = json.loads(cleaned)
            except json.JSONDecodeError:
                return [
                    Finding(
                        rule_id="LLM-RAW",
                        title="LLM returned non-JSON content",
                        severity="info",
                        file=str(file_path),
                        line=0,
                        detail=raw[:600],
                        engine="llm",
                    )
                ]

        items = payload.get("findings") or []
        results: list[Finding] = []
        for item in items:
            sev = str(item.get("severity", "medium")).lower()
            if sev not in {"low", "medium", "high", "critical"}:
                sev = "medium"
            results.append(
                Finding(
                    rule_id="LLM",
                    title=str(item.get("title") or "LLM finding")[:120],
                    severity=sev,
                    file=str(file_path),
                    line=int(item.get("line") or 0),
                    detail=str(item.get("detail") or "")[:600],
                    engine="llm",
                )
            )
        return results

    @staticmethod
    def _error(file_path: Path, detail: str) -> Finding:
        return Finding(
            rule_id="LLM-ERR",
            title="LLM analysis failed",
            severity="info",
            file=str(file_path),
            line=0,
            detail=detail,
            engine="llm",
        )
