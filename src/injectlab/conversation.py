"""Provider-neutral conversation types shared by targets, the agent loop and oracles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class ToolSpec:
    """A tool as advertised to the model."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolCall:
        return cls(id=str(d.get("id", "")), name=str(d["name"]), arguments=dict(d.get("arguments") or {}))


@dataclass
class Message:
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None
    # Opaque provider-specific payload (e.g. Anthropic content blocks incl. thinking blocks)
    # that must be replayed verbatim on the next request. Never shown to oracles.
    provider_raw: Any = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            d["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]
        if self.tool_call_id is not None:
            d["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            d["name"] = self.name
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Message:
        return cls(
            role=d["role"],
            content=d.get("content") or "",
            tool_calls=[ToolCall.from_dict(t) for t in d.get("tool_calls") or []],
            tool_call_id=d.get("tool_call_id"),
            name=d.get("name"),
        )


@dataclass
class ModelResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    provider_raw: Any = None


@dataclass
class TrialHints:
    """Side-channel information that ONLY the built-in mock models consume.

    Real adapters ignore this entirely; it lets deterministic mock models behave like an agent that
    knows how to perform the benign user task (they cannot "understand" the task otherwise).
    """

    plan: list[dict[str, Any]] = field(default_factory=list)
    reference_answer: str = ""
    trusted_tools: list[str] = field(default_factory=list)
    canary: str = ""
