"""Adapter for the Anthropic Messages API (``POST /v1/messages``) with ``tool_use`` / ``tool_result`` blocks.

Implemented over plain HTTP so injectlab keeps a single runtime dependency. Assistant turns are
replayed with their original content blocks (including any ``thinking`` blocks), which the API
requires when continuing a tool-use loop.
"""

from __future__ import annotations

import os
from typing import Any

from injectlab.conversation import Message, ModelResponse, ToolCall, ToolSpec, TrialHints
from injectlab.targets.base import Target, TargetError
from injectlab.targets.http import RetryPolicy, expand_env, post_json

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicTarget(Target):
    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        api_key_env: str = "ANTHROPIC_API_KEY",
        api_key: str | None = None,
        max_tokens: int = 4096,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        timeout: float = 120.0,
        retry: RetryPolicy | None = None,
        require_key: bool = True,
    ) -> None:
        self.model = model
        self.base_url = (
            base_url or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
        ).rstrip("/")
        self._api_key = api_key if api_key is not None else os.environ.get(api_key_env)
        if require_key and not self._api_key:
            raise TargetError(f"API key not found: set the {api_key_env} environment variable")
        self.max_tokens = max_tokens
        self.headers = {k: expand_env(v) for k, v in (headers or {}).items()}
        self.params = dict(params or {})
        self.timeout = timeout
        self.retry = retry or RetryPolicy()
        self.name = f"anthropic:{model}"

    # -- wire format -------------------------------------------------------------------------
    @staticmethod
    def to_wire(messages: list[Message]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        wire: list[dict[str, Any]] = []

        def push(role: str, blocks: list[dict[str, Any]]) -> None:
            if wire and wire[-1]["role"] == role:
                wire[-1]["content"].extend(blocks)
            else:
                wire.append({"role": role, "content": list(blocks)})

        for m in messages:
            if m.role == "system":
                system_parts.append(m.content)
            elif m.role == "user":
                push("user", [{"type": "text", "text": m.content}])
            elif m.role == "tool":
                push(
                    "user",
                    [
                        {
                            "type": "tool_result",
                            "tool_use_id": m.tool_call_id or "",
                            "content": m.content or "(empty)",
                        }
                    ],
                )
            elif m.role == "assistant":
                if isinstance(m.provider_raw, list) and m.provider_raw:
                    push("assistant", m.provider_raw)
                    continue
                blocks: list[dict[str, Any]] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
                if blocks:
                    push("assistant", blocks)
        if wire and wire[0]["role"] != "user":
            wire.insert(0, {"role": "user", "content": [{"type": "text", "text": "(conversation start)"}]})
        return "\n\n".join(system_parts), wire

    @staticmethod
    def to_wire_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]

    @staticmethod
    def parse_response(data: dict[str, Any]) -> ModelResponse:
        if data.get("type") == "error":
            raise TargetError(f"API error: {data.get('error')}")
        blocks = data.get("content")
        if not isinstance(blocks, list):
            raise TargetError("response has no content blocks")
        texts: list[str] = []
        calls: list[ToolCall] = []
        for b in blocks:
            if b.get("type") == "text":
                texts.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                inp = b.get("input")
                calls.append(
                    ToolCall(
                        id=b.get("id", ""),
                        name=b.get("name", ""),
                        arguments=inp if isinstance(inp, dict) else {"_value": inp},
                    )
                )
        return ModelResponse(
            content="".join(texts),
            tool_calls=calls,
            stop_reason=data.get("stop_reason"),
            usage=data.get("usage") or {},
            provider_raw=blocks,
        )

    def build_body(self, messages: list[Message], tools: list[ToolSpec]) -> dict[str, Any]:
        system, wire = self.to_wire(messages)
        body: dict[str, Any] = {"model": self.model, "max_tokens": self.max_tokens, "messages": wire}
        if system:
            body["system"] = system
        if tools:
            body["tools"] = self.to_wire_tools(tools)
        body.update(self.params)
        return body

    def complete(
        self, messages: list[Message], tools: list[ToolSpec], *, hints: TrialHints | None = None
    ) -> ModelResponse:
        headers = {"anthropic-version": ANTHROPIC_VERSION, **self.headers}
        if self._api_key:
            headers.setdefault("x-api-key", self._api_key)
        data = post_json(
            f"{self.base_url}/v1/messages",
            self.build_body(messages, tools),
            headers,
            timeout=self.timeout,
            retry=self.retry,
        )
        return self.parse_response(data)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": "anthropic",
            "model": self.model,
            "base_url": self.base_url,
            "max_tokens": self.max_tokens,
            "params": self.params,
        }
