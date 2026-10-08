"""The agent loop: model turn -> sandboxed tool execution -> tool results -> next turn."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from injectlab.conversation import Message, TrialHints
from injectlab.sandbox import ToolExecution, ToolSandbox
from injectlab.targets.base import Target, TargetError


@dataclass
class Transcript:
    messages: list[Message] = field(default_factory=list)
    executions: list[ToolExecution] = field(default_factory=list)
    turns: int = 0
    stop_reason: str = ""
    error: str | None = None
    usage: list[dict[str, Any]] = field(default_factory=list)

    @property
    def assistant_texts(self) -> list[str]:
        return [m.content for m in self.messages if m.role == "assistant" and m.content]

    @property
    def final_output(self) -> str:
        for m in reversed(self.messages):
            if m.role == "assistant" and m.content:
                return m.content
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages": [m.to_dict() for m in self.messages],
            "tool_executions": [e.to_dict() for e in self.executions],
            "turns": self.turns,
            "stop_reason": self.stop_reason,
            "error": self.error,
        }


def run_agent(
    target: Target,
    sandbox: ToolSandbox,
    *,
    system_prompt: str,
    user_message: str,
    max_turns: int = 8,
    hints: TrialHints | None = None,
    max_tool_calls_per_turn: int = 16,
) -> Transcript:
    """Run the tool-calling loop until the model answers without tool calls or ``max_turns`` is hit."""
    tools = sandbox.specs()
    t = Transcript(messages=[Message("system", system_prompt), Message("user", user_message)])
    for turn in range(1, max_turns + 1):
        try:
            resp = target.complete(list(t.messages), tools, hints=hints)
        except TargetError as e:
            t.error = str(e)
            t.stop_reason = "error"
            break
        t.turns = turn
        if resp.usage:
            t.usage.append(resp.usage)
        calls = resp.tool_calls[:max_tool_calls_per_turn]
        t.messages.append(
            Message("assistant", resp.content or "", tool_calls=calls, provider_raw=resp.provider_raw)
        )
        if not calls:
            t.stop_reason = resp.stop_reason or "end_turn"
            break
        for call in calls:
            result = sandbox.execute(call, turn)
            t.messages.append(Message("tool", result, tool_call_id=call.id, name=call.name))
    else:
        t.stop_reason = "max_turns"
    t.executions = list(sandbox.executions)
    return t
