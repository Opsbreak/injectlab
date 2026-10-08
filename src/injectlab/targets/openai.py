"""Adapter for any OpenAI-compatible ``/chat/completions`` endpoint with function/tool calling.

Works with OpenAI, Azure OpenAI-compatible gateways, vLLM, Ollama, LiteLLM, OpenRouter and similar.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from injectlab.conversation import Message, ModelResponse, ToolCall, ToolSpec, TrialHints
from injectlab.targets.base import Target, TargetError
from injectlab.targets.http import RetryPolicy, expand_env, post_json


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if raw is None or raw == "":
        return {}
    try:
        val = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {"_raw_arguments": str(raw)}
    return val if isinstance(val, dict) else {"_value": val}


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # content parts
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return str(content)


class OpenAITarget(Target):
    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        api_key_env: str = "OPENAI_API_KEY",
        api_key: str | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        timeout: float = 60.0,
        retry: RetryPolicy | None = None,
        require_key: bool = True,
    ) -> None:
        self.model = model
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip(
            "/"
        )
        self.api_key_env = api_key_env
        self._api_key = api_key if api_key is not None else os.environ.get(api_key_env)
        if require_key and not self._api_key:
            raise TargetError(f"API key not found: set the {api_key_env} environment variable")
        self.headers = {k: expand_env(v) for k, v in (headers or {}).items()}
        self.params = dict(params or {})
        self.timeout = timeout
        self.retry = retry or RetryPolicy()
        self.name = f"openai:{model}"

    # -- wire format -------------------------------------------------------------------------
    @staticmethod
    def to_wire_messages(messages: list[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "assistant":
                d: dict[str, Any] = {"role": "assistant", "content": m.content or None}
                if m.tool_calls:
                    d["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                            },
                        }
                        for tc in m.tool_calls
                    ]
                out.append(d)
            elif m.role == "tool":
                out.append({"role": "tool", "tool_call_id": m.tool_call_id or "", "content": m.content})
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    @staticmethod
    def to_wire_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
            }
            for t in tools
        ]

    @staticmethod
    def parse_response(data: dict[str, Any]) -> ModelResponse:
        if "error" in data and not data.get("choices"):
            raise TargetError(f"endpoint returned an error: {data['error']}")
        choices = data.get("choices") or []
        if not choices:
            raise TargetError("response has no choices")
        choice = choices[0]
        msg = choice.get("message") or {}
        calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            calls.append(
                ToolCall(
                    id=tc.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                    name=fn.get("name", ""),
                    arguments=_parse_arguments(fn.get("arguments")),
                )
            )
        if not calls and msg.get("function_call"):  # legacy functions API
            fc = msg["function_call"]
            calls.append(
                ToolCall(
                    f"call_{uuid.uuid4().hex[:12]}", fc.get("name", ""), _parse_arguments(fc.get("arguments"))
                )
            )
        text = _content_text(msg.get("content"))
        if not text and msg.get("refusal"):
            text = str(msg["refusal"])
        return ModelResponse(
            content=text,
            tool_calls=calls,
            stop_reason=choice.get("finish_reason"),
            usage=data.get("usage") or {},
        )

    def build_body(self, messages: list[Message], tools: list[ToolSpec]) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "messages": self.to_wire_messages(messages)}
        if tools:
            body["tools"] = self.to_wire_tools(tools)
            body["tool_choice"] = "auto"
        body.update(self.params)
        return body

    def complete(
        self, messages: list[Message], tools: list[ToolSpec], *, hints: TrialHints | None = None
    ) -> ModelResponse:
        headers = dict(self.headers)
        if self._api_key:
            headers.setdefault("Authorization", f"Bearer {self._api_key}")
        data = post_json(
            f"{self.base_url}/chat/completions",
            self.build_body(messages, tools),
            headers,
            timeout=self.timeout,
            retry=self.retry,
        )
        return self.parse_response(data)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": "openai",
            "model": self.model,
            "base_url": self.base_url,
            "params": self.params,
        }
