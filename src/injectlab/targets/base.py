"""Target interface: one model call given the conversation so far."""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Any

from injectlab.conversation import Message, ModelResponse, ToolSpec, TrialHints


class TargetError(RuntimeError):
    """A target failed (after retries). The trial is recorded as an error, not as a defence."""


class Target(ABC):
    name: str = "target"

    @abstractmethod
    def complete(
        self, messages: list[Message], tools: list[ToolSpec], *, hints: TrialHints | None = None
    ) -> ModelResponse:
        """Return the model's next assistant turn."""

    def describe(self) -> dict[str, Any]:
        """Non-secret description stored in results metadata."""
        return {"name": self.name}


class RateLimitedTarget(Target):
    """Wraps a target so that calls across all worker threads respect ``rate`` requests/second."""

    def __init__(self, inner: Target, rate: float) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.inner = inner
        self.name = inner.name
        self.interval = 1.0 / rate
        self._lock = threading.Lock()
        self._next = 0.0

    def _acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + self.interval
        if wait > 0:
            time.sleep(wait)

    def complete(
        self, messages: list[Message], tools: list[ToolSpec], *, hints: TrialHints | None = None
    ) -> ModelResponse:
        self._acquire()
        return self.inner.complete(messages, tools, hints=hints)

    def describe(self) -> dict[str, Any]:
        return {**self.inner.describe(), "rate_limit_rps": 1.0 / self.interval}
