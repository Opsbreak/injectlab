"""Generic JSON webhook target for custom agent backends.

injectlab POSTs the provider-neutral conversation (or a custom body template) and extracts the
assistant message and tool calls from the response with JSONPath-like expressions::

    type: http
    url: https://agent.internal.example/v1/step
    headers: {Authorization: "Bearer ${AGENT_TOKEN}"}
    body:                       # optional; "$messages", "$tools", "$system", "$last_user" are substituted
      conversation: $messages
      tools: $tools
    response:
      content: $.output.text
      tool_calls: $.output.tool_calls
      tool_name: $.name           # relative to each tool-call element
      tool_arguments: $.arguments # object or JSON string
      tool_id: $.id
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from injectlab.conversation import Message, ModelResponse, ToolCall, ToolSpec, TrialHints
from injectlab.targets.base import Target, TargetError
from injectlab.targets.http import RetryPolicy, expand_env, post_json

_TOKEN_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_\-]*)|\[(\d+)\]|\['([^']*)'\]|\[\"([^\"]*)\"\]")


class PathError(KeyError):
    pass


def jsonpath_get(obj: Any, path: str, default: Any = None) -> Any:
    """Resolve a small JSONPath subset: ``$``, ``.key``, ``['key']``, ``[n]`` (negative not supported)."""
    if not path or path == "$":
        return obj
    if not path.startswith("$"):
        path = "$." + path
    rest = path[1:]
    pos = 0
    cur = obj
    while pos < len(rest):
        m = _TOKEN_RE.match(rest, pos)
        if not m:
            raise PathError(f"bad path syntax at {rest[pos:]!r} in {path!r}")
        key = m.group(1) or m.group(3) or m.group(4)
        idx = m.group(2)
        if key is not None:
            if not isinstance(cur, dict) or key not in cur:
                return default
            cur = cur[key]
        else:
            i = int(idx)
            if not isinstance(cur, list) or i >= len(cur):
                return default
            cur = cur[i]
        pos = m.end()
    return cur


def _substitute(template: Any, values: dict[str, Any]) -> Any:
    if isinstance(template, str) and template in values:
        return values[template]
    if isinstance(template, str):
        return expand_env(template)
    if isinstance(template, list):
        return [_substitute(x, values) for x in template]
    if isinstance(template, dict):
        return {k: _substitute(v, values) for k, v in template.items()}
    return template


class WebhookTarget(Target):
    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        response: dict[str, str] | None = None,
        timeout: float = 60.0,
        retry: RetryPolicy | None = None,
        name: str | None = None,
    ) -> None:
        self.url = url
        self.header_templates = dict(headers or {})
        self.body_template = body
        r = response or {}
        self.content_path = r.get("content", "$.content")
        self.tool_calls_path = r.get("tool_calls", "$.tool_calls")
        self.tool_name_path = r.get("tool_name", "$.name")
        self.tool_args_path = r.get("tool_arguments", "$.arguments")
        self.tool_id_path = r.get("tool_id", "$.id")
        self.timeout = timeout
        self.retry = retry or RetryPolicy()
        self.name = name or f"http:{url}"

    def build_body(self, messages: list[Message], tools: list[ToolSpec]) -> dict[str, Any]:
        wire_messages = [m.to_dict() for m in messages]
        wire_tools = [t.to_dict() for t in tools]
        if self.body_template is None:
            return {"messages": wire_messages, "tools": wire_tools}
        last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        values = {
            "$messages": wire_messages,
            "$tools": wire_tools,
            "$system": system,
            "$last_user": last_user,
        }
        out = _substitute(self.body_template, values)
        if not isinstance(out, dict):
            raise TargetError("body template must produce a JSON object")
        return out

    def parse_response(self, data: dict[str, Any]) -> ModelResponse:
        content = jsonpath_get(data, self.content_path, "") or ""
        if not isinstance(content, str):
            content = json.dumps(content)
        calls: list[ToolCall] = []
        raw_calls = jsonpath_get(data, self.tool_calls_path, []) or []
        if not isinstance(raw_calls, list):
            raise TargetError(f"{self.tool_calls_path} did not resolve to a list")
        for rc in raw_calls:
            name = jsonpath_get(rc, self.tool_name_path)
            if not name:
                raise TargetError(f"tool call without a name at {self.tool_name_path}: {rc!r}")
            args = jsonpath_get(rc, self.tool_args_path, {})
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args.strip() else {}
                except json.JSONDecodeError:
                    args = {"_raw_arguments": args}
            if not isinstance(args, dict):
                args = {"_value": args}
            cid = jsonpath_get(rc, self.tool_id_path) or f"call_{uuid.uuid4().hex[:12]}"
            calls.append(ToolCall(id=str(cid), name=str(name), arguments=args))
        return ModelResponse(content=content, tool_calls=calls, stop_reason=None)

    def complete(
        self, messages: list[Message], tools: list[ToolSpec], *, hints: TrialHints | None = None
    ) -> ModelResponse:
        headers = {k: expand_env(v) for k, v in self.header_templates.items()}
        data = post_json(
            self.url, self.build_body(messages, tools), headers, timeout=self.timeout, retry=self.retry
        )
        return self.parse_response(data)

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "type": "http", "url": self.url}
