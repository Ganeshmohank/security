"""LLM-backed code reviewer.

Supports two providers out of the box:

* ``openai``     - api.openai.com, e.g. gpt-4o-mini, gpt-4.1-mini.
* ``openrouter`` - openrouter.ai, e.g. deepseek/deepseek-chat.

Provider is picked automatically from whichever of ``OPENAI_API_KEY`` /
``OPENROUTER_API_KEY`` is set, unless the caller forces it via the
``provider`` argument. The engine is optional: when no key is available
it returns a single informational finding so the rest of the scan keeps
working.

Responses are requested in JSON object mode, which removes the fragile
regex parser the previous implementation relied on.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import List, Optional

from ..core.finding import Finding


# Retry configuration for transient failures (429, 5xx).
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 4.0


OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

DEFAULT_MODEL = {
    "openai": "gpt-4o-mini",
    "openrouter": "deepseek/deepseek-chat",
}

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
    """Provider-agnostic LLM wrapper.

    ``provider`` accepts ``"openai"``, ``"openrouter"``, or ``"auto"``.
    In auto mode we prefer OpenAI when its key is present, falling back
    to OpenRouter.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
        provider: str = "auto",
    ) -> None:
        self.provider = self._resolve_provider(provider, api_key)
        self.api_key = api_key or self._key_for(self.provider)
        self.model = model or DEFAULT_MODEL[self.provider]
        self.timeout = timeout

    @staticmethod
    def _resolve_provider(provider: str, explicit_key: Optional[str]) -> str:
        provider = (provider or "auto").lower()
        if provider in {"openai", "openrouter"}:
            return provider
        # auto: prefer whichever env var is set, default to openai.
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("OPENROUTER_API_KEY"):
            return "openrouter"
        return "openai"

    @staticmethod
    def _key_for(provider: str) -> Optional[str]:
        if provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        return os.getenv("OPENROUTER_API_KEY")

    # ------------------------------------------------------------------

    def analyze(self, file_path: Path) -> List[Finding]:
        if not self.api_key:
            env_name = (
                "OPENAI_API_KEY"
                if self.provider == "openai"
                else "OPENROUTER_API_KEY"
            )
            return [
                Finding(
                    rule_id="LLM-CFG",
                    title="LLM analysis skipped",
                    severity="info",
                    file=str(file_path),
                    line=0,
                    detail=f"Set {env_name} (or pass --api-key) to enable LLM review.",
                    engine="llm",
                )
            ]

        try:
            source = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            return [self._error(file_path, f"Cannot read file: {exc}")]

        snippet = (
            source
            if len(source) <= _MAX_SOURCE_CHARS
            else source[:_MAX_SOURCE_CHARS] + "\n# ...truncated..."
        )

        try:
            raw = self._call(snippet)
        except Exception as exc:
            return [self._error(file_path, f"{self.provider} call failed: {exc}")]

        return self._decode(raw, file_path)

    # ------------------------------------------------------------------

    def _endpoint(self) -> str:
        return OPENAI_URL if self.provider == "openai" else OPENROUTER_URL

    def _headers(self) -> dict:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.provider == "openrouter":
            headers["X-Title"] = "secscan"
            headers["HTTP-Referer"] = "https://github.com/"
        return headers

    def _call(self, source: str) -> str:
        try:
            import requests
        except ImportError as exc:
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

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            resp = requests.post(
                self._endpoint(),
                headers=self._headers(),
                data=json.dumps(body),
                timeout=self.timeout,
            )

            # Retry 429 + 5xx with exponential backoff; fail fast on 4xx.
            if resp.status_code in (429,) or 500 <= resp.status_code < 600:
                retry_after = _parse_retry_after(resp)
                if attempt == _MAX_RETRIES - 1:
                    raise RuntimeError(
                        f"{resp.status_code} {resp.reason}: "
                        f"{_body_hint(resp)}"
                    )
                sleep_for = retry_after or (_BASE_BACKOFF_SECONDS * (2 ** attempt))
                time.sleep(sleep_for)
                continue

            if not resp.ok:
                raise RuntimeError(
                    f"{resp.status_code} {resp.reason}: {_body_hint(resp)}"
                )

            return resp.json()["choices"][0]["message"]["content"]

        if last_exc:
            raise last_exc
        raise RuntimeError("unreachable")

    def _decode(self, raw: str, file_path: Path) -> List[Finding]:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
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


def _parse_retry_after(resp) -> float | None:
    """Honour ``Retry-After`` when the provider sets it."""
    header = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
    if not header:
        return None
    try:
        return float(header)
    except ValueError:
        return None


def _body_hint(resp) -> str:
    """Extract the most useful line of error text from the JSON body."""
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:200]
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        msg = err.get("message") or err.get("code") or ""
        return str(msg)[:300]
    return str(body)[:300]
