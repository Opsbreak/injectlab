"""JSON-over-HTTP with timeouts and retries (exponential backoff with full jitter, Retry-After aware)."""

from __future__ import annotations

import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from injectlab.targets.base import TargetError

RETRY_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})


class HTTPStatusError(TargetError):
    def __init__(self, status: int, body: str, url: str) -> None:
        super().__init__(f"HTTP {status} from {url}: {body[:500]}")
        self.status = status
        self.body = body


@dataclass
class RetryPolicy:
    max_retries: int = 4
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    retry_statuses: frozenset[int] = RETRY_STATUSES
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)
    rng: random.Random = field(default_factory=random.Random, repr=False)

    def delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), self.backoff_max)
        cap = min(self.backoff_max, self.backoff_base * (2**attempt))
        return self.rng.uniform(cap / 2, cap)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None  # HTTP-date form: fall back to exponential backoff


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value: str) -> str:
    """Expand ``${VAR}`` references; missing variables raise so secrets never go out empty."""

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in os.environ:
            raise TargetError(f"environment variable {name} is not set")
        return os.environ[name]

    return _ENV_RE.sub(sub, value)


def post_json(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    timeout: float = 60.0,
    retry: RetryPolicy | None = None,
) -> dict[str, Any]:
    retry = retry or RetryPolicy()
    data = json.dumps(body).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "injectlab"}
    hdrs.update(headers)
    last_error: Exception | None = None
    for attempt in range(retry.max_retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        retry_after: float | None = None
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as e:
                raise TargetError(f"non-JSON response from {url}: {raw[:200]}") from e
            if not isinstance(parsed, dict):
                raise TargetError(f"expected a JSON object from {url}")
            return parsed
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace") if e.fp else ""
            err = HTTPStatusError(e.code, text, url)
            if e.code not in retry.retry_statuses:
                raise err from None
            last_error = err
            retry_after = _parse_retry_after(e.headers.get("Retry-After") if e.headers else None)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_error = TargetError(f"request to {url} failed: {e}")
        if attempt < retry.max_retries:
            retry.sleep(retry.delay(attempt, retry_after))
    raise TargetError(f"giving up after {retry.max_retries + 1} attempts: {last_error}") from last_error
