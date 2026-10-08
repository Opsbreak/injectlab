"""Sandboxed mock tools: nothing is ever executed, every call is recorded."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from injectlab.conversation import ToolCall, ToolSpec
from injectlab.predicates import check_conditions
from injectlab.schema import validate
from injectlab.suite import ToolDef
from injectlab.templating import render


@dataclass
class ToolExecution:
    turn: int
    id: str
    name: str
    arguments: dict[str, Any]
    result: str
    known_tool: bool = True
    schema_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn": self.turn,
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
            "result": self.result,
            "known_tool": self.known_tool,
            "schema_errors": self.schema_errors,
        }


def _to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


class ToolSandbox:
    """Executes tool calls against mock behaviours declared in the scenario."""

    def __init__(
        self,
        tools: list[ToolDef],
        documents: dict[str, str],
        variables: dict[str, Any],
        *,
        result_template: str | None = None,
        max_result_chars: int | None = None,
    ) -> None:
        self.tools = {t.name: t for t in tools}
        self.documents = documents
        self.variables = variables
        self.result_template = result_template
        self.max_result_chars = max_result_chars
        self.executions: list[ToolExecution] = []

    def specs(self) -> list[ToolSpec]:
        return [ToolSpec(t.name, t.description, t.parameters) for t in self.tools.values()]

    def _behaviour(self, spec: dict[str, Any], args: dict[str, Any]) -> str:
        if "document" in spec:
            return self.documents[spec["document"]]
        if "template" in spec:
            return render(spec["template"], {**self.variables, "args": args}, strict=False, max_passes=1)
        if "value" in spec:
            return render(
                _to_text(spec["value"]), {**self.variables, "args": args}, strict=False, max_passes=1
            )
        return json.dumps({"status": "ok"})

    def _result_for(self, tool: ToolDef, args: dict[str, Any]) -> str:
        mock = tool.mock
        kind = mock["type"]
        if kind == "document":
            return self.documents[mock["document"]]
        if kind == "static":
            return render(_to_text(mock.get("value", {"status": "ok"})), self.variables, strict=False)
        if kind == "template":
            return render(mock["template"], {**self.variables, "args": args}, strict=False, max_passes=1)
        if kind == "error":
            return json.dumps({"error": mock.get("message", "tool failed")})
        if kind == "router":
            for route in mock.get("routes") or []:
                if check_conditions(route.get("when") or [], args):
                    return self._behaviour(route, args)
            default = mock.get("default", {"value": {"status": "ok"}})
            return self._behaviour(default if isinstance(default, dict) else {"value": default}, args)
        raise ValueError(f"unknown mock type {kind}")  # pragma: no cover

    def execute(self, call: ToolCall, turn: int) -> str:
        tool = self.tools.get(call.name)
        if tool is None:
            result = json.dumps({"error": f"unknown tool '{call.name}'"})
            self.executions.append(
                ToolExecution(turn, call.id, call.name, call.arguments, result, known_tool=False)
            )
            return result
        errors = validate(call.arguments, tool.parameters)
        result = self._result_for(tool, call.arguments)
        if self.max_result_chars and len(result) > self.max_result_chars:
            result = result[: self.max_result_chars] + "\n[truncated]"
        if self.result_template:
            # Plain replacement (single pass) so attacker text inside the result is never re-rendered.
            result = self.result_template.replace("{{tool}}", call.name).replace("{{result}}", result)
        self.executions.append(ToolExecution(turn, call.id, call.name, call.arguments, result, True, errors))
        return result
