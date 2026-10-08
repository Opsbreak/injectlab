from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"
PAYLOADS = ROOT / "payloads"

Reply = tuple[int, dict[str, str], Any]  # status, headers, JSON body (or raw str)


@dataclass
class FakeServer:
    """A local HTTP server that replays scripted replies and records every request."""

    url: str = ""
    replies: list[Reply | Callable[[dict[str, Any]], Reply]] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    delay: float = 0.0
    default: Reply | Callable[[dict[str, Any]], Reply] | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def push(self, *replies: Reply | Callable[[dict[str, Any]], Reply]) -> None:
        self.replies.extend(replies)

    def next_reply(self, req: dict[str, Any]) -> Reply:
        with self.lock:
            item = self.replies.pop(0) if self.replies else self.default
        if item is None:
            return (500, {}, {"error": "no scripted reply"})
        return item(req) if callable(item) else item


@pytest.fixture
def fake_server() -> Iterator[FakeServer]:
    state = FakeServer()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = raw
            req = {
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
            state.requests.append(req)
            if state.delay:
                time.sleep(state.delay)
            status, headers, payload = state.next_reply(req)
            data = payload if isinstance(payload, str) else json.dumps(payload)
            encoded = data.encode("utf-8")
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def log_message(self, *args: Any) -> None:  # silence
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def scenarios():
    from injectlab.suite import load_scenarios

    return {s.id: s for s in load_scenarios([SCENARIOS])}


@pytest.fixture(scope="session")
def payloads():
    from injectlab.suite import load_payloads

    return {p.id: p for p in load_payloads([PAYLOADS])}


@pytest.fixture
def fast_retry():
    from injectlab.targets.http import RetryPolicy

    sleeps: list[float] = []
    policy = RetryPolicy(max_retries=3, backoff_base=0.01, backoff_max=0.05, sleep=sleeps.append)
    policy.sleeps = sleeps  # type: ignore[attr-defined]
    return policy
