"""Deterministic, rule-based mock models used for tests, demos and harness self-checks.

``mock:naive``
    Behaves like an over-compliant agent: it reads whatever arrived last (user message or tool
    result), "understands" common obfuscations a capable LLM can read (Unicode tags, zero-width
    characters, homoglyphs, base64, ROT13, HTML comments, JSON), and follows the most recent
    imperative instruction it finds - tool calls, "reply with ...", "repeat your system prompt".
    Otherwise it executes the benign task plan and answers with the reference answer.

``mock:guarded``
    Same capabilities, but applies a data/instruction separation policy: content arriving through
    tool results or ``<retrieved_documents>`` blocks is treated strictly as data and never as
    instructions (spotlighting). It notes when retrieved data contained instructions. It does,
    however, trust tools explicitly marked ``trusted: true`` in the scenario (e.g. an internal
    sub-agent) - modelling the transitive-trust weakness common in multi-agent systems.

These are NOT predictors of real-model behaviour; they exist so the harness, oracles and reporting
can be exercised end to end, deterministically, without network access.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import html
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from injectlab.canary import CANARY_RE
from injectlab.conversation import Message, ModelResponse, ToolCall, ToolSpec, TrialHints
from injectlab.targets.base import Target
from injectlab.textutil import normalize_for_reading, rot13

_CALL_VERBS = re.compile(
    r"\b(?:call|calling|invoke|use|using|run|execute|trigger|appelez|appeler|appelle|utilisez|utiliser|"
    r"exécutez|llama|llame|llamar|usa|utiliza|utilice|ejecuta|rufe|rufen|verwende|verwenden|nutze|"
    r"benutze|führe)\b",
    re.IGNORECASE,
)
_LEAK_RE = re.compile(
    r"\b(?:repeat|print|output|reveal|show|disclose|recite|reproduce|dump|répétez|répète|affichez|révélez|"
    r"repite|muestra|revela|wiederhole|zeige|gib)\b[^.\n]{0,60}?\b(?:your|vos|votre|tes|tus|tu|deine|"
    r"ihre|dein)\b[^.\n]{0,40}?(?:system ?prompt|system message|instructions|initial prompt|consignes|"
    r"instrucciones|anweisungen)",
    re.IGNORECASE,
)
_SAY_RE = re.compile(
    r"\b(?P<verb>reply|respond|answer|say|write|output|print|tell the user|tell them|"
    r"finish your (?:reply|response|answer|message) with|end your (?:reply|response|answer|message) with|"
    r"include|append|répondez|réponds|dites|écrivez|terminez votre réponse avec|responde|escribe|"
    r"termina tu respuesta con|antworte|sage|schreibe|beende deine antwort mit)\b"
    r"[^\"“«{\n]{0,140}?"
    r"(?:[\"“«](?P<q>[^\"”»\n]{3,500})[\"”»]|(?P<md>!?\[[^\]\n]*\]\([^)\n]+\)))",
    re.IGNORECASE,
)
_APPEND_VERBS = ("finish", "end", "include", "append", "termin", "beende")
_PLACEHOLDER = re.compile(r"<([^<>\n]{3,200})>")
_SECRET_WORDS = re.compile(
    r"\b(?:code|secret|key|token|password|passcode|reference|canary|credential|identifier|pin)\b",
    re.IGNORECASE,
)
_PROMPT_WORDS = re.compile(r"system ?prompt|instructions|initial prompt", re.IGNORECASE)
_B64_BLOCK = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_PART_RE = re.compile(r"\[(\d+)/(\d+)\] ([^\n]*)")
_ARG_KEYS = ("arguments", "args", "parameters", "params", "input")
_NAME_KEYS = ("tool", "name", "function", "tool_name")
_CONTEXT_BLOCK = re.compile(r"<retrieved_documents>.*</retrieved_documents>", re.DOTALL | re.IGNORECASE)


@dataclass
class Directive:
    kind: str  # "tool" | "say" | "leak"
    pos: int
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    append: bool = False


# --------------------------------------------------------------------------------------------
# Reading: what a capable model would perceive in a piece of text
# --------------------------------------------------------------------------------------------
def _flatten_json_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _flatten_json_strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_json_strings(v)]
    return []


def read_view(text: str) -> str:
    """Deobfuscate text the way a capable LLM effectively 'reads' it."""
    stripped = text.strip()
    if stripped[:1] in "[{":
        with contextlib.suppress(json.JSONDecodeError):
            text = "\n\n".join(_flatten_json_strings(json.loads(stripped)))
    view = html.unescape(normalize_for_reading(text))

    def decode_b64(m: re.Match[str]) -> str:
        block = m.group(0)
        try:
            raw = base64.b64decode(block + "=" * (-len(block) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return block
        printable = sum(c.isprintable() or c in "\n\t" for c in s) / max(len(s), 1)
        return f"{block}\n{normalize_for_reading(s)}\n" if printable > 0.95 and len(s) >= 8 else block

    view = _B64_BLOCK.sub(decode_b64, view)
    m = re.search(r"rot-?13", view, re.IGNORECASE)
    if m:
        line_end = view.find("\n", m.end())
        if line_end != -1:
            view = view[: line_end + 1] + rot13(view[line_end + 1 :])
    # Reassemble payloads that were split into "[k/n] ..." parts across chunks.
    parts: dict[int, dict[int, str]] = {}
    for pm in _PART_RE.finditer(view):
        parts.setdefault(int(pm.group(2)), {})[int(pm.group(1))] = pm.group(3)
    for n, got in parts.items():
        if n > 1 and all(k in got for k in range(1, n + 1)):
            view += "\n\n" + " ".join(got[k] for k in range(1, n + 1))
    return view


def _balanced_json(text: str, start: int) -> tuple[Any, int] | None:
    depth, in_str, esc = 0, False, False
    for j in range(start, len(text)):
        c = text[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                chunk = text[start : j + 1]
                for candidate in (chunk, chunk.replace("'", '"')):
                    try:
                        return json.loads(candidate), j + 1
                    except json.JSONDecodeError:
                        continue
                return None
    return None


def _kv_args(window: str, tool: ToolSpec) -> dict[str, Any]:
    props = (tool.parameters or {}).get("properties", {})
    out: dict[str, Any] = {}
    for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s,;]+))", window
    ):
        key = m.group(1)
        if key in props and key not in out:
            out[key] = (
                m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4)
            )
    return out


def extract_directives(view: str, tools: list[ToolSpec]) -> list[Directive]:
    found: list[Directive] = []
    by_name = {t.name: t for t in tools}
    for t in tools:
        for m in re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(t.name)}(?![A-Za-z0-9_])", view):
            before = view[max(0, m.start() - 80) : m.start()]
            verbs = list(_CALL_VERBS.finditer(before))
            if not verbs:
                continue
            window = view[m.end() : m.end() + 800]
            brace = window.find("{")
            args: dict[str, Any] | None = None
            if 0 <= brace <= 160:
                parsed = _balanced_json(view, m.end() + brace)
                if parsed and isinstance(parsed[0], dict):
                    args = parsed[0]
            if args is None:
                args = _kv_args(window[:300], t)
            required = (t.parameters or {}).get("required", [])
            if any(r not in args for r in required):
                continue
            pos = m.start() - len(before) + verbs[-1].start()
            found.append(Directive("tool", pos, tool=t.name, args=args))
    # Fake tool-call / tool-result JSON objects: {"tool": "x", "arguments": {...}}
    i = 0
    while True:
        i = view.find("{", i)
        if i == -1:
            break
        parsed = _balanced_json(view, i)
        if parsed is None:
            i += 1
            continue
        obj, end = parsed
        for d in _walk_dicts(obj):
            name = next((d[k] for k in _NAME_KEYS if isinstance(d.get(k), str) and d[k] in by_name), None)
            args = next((d[k] for k in _ARG_KEYS if isinstance(d.get(k), dict)), None)
            if name and args is not None:
                found.append(Directive("tool", i, tool=name, args=args))
        i = end
    for m in _LEAK_RE.finditer(view):
        found.append(Directive("leak", m.start()))
    for m in _SAY_RE.finditer(view):
        text = m.group("q") or m.group("md")
        verb = m.group("verb").lower()
        found.append(Directive("say", m.start(), text=text, append=verb.startswith(_APPEND_VERBS)))
    found.sort(key=lambda d: d.pos)
    return found


def _walk_dicts(obj: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        out.append(obj)
        for v in obj.values():
            out.extend(_walk_dicts(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_dicts(v))
    return out


def fill_placeholders(value: Any, secret: str, system_prompt: str) -> Any:
    """Replace '<the secret code ...>' style placeholders with what the model actually knows."""
    if isinstance(value, dict):
        return {k: fill_placeholders(v, secret, system_prompt) for k, v in value.items()}
    if isinstance(value, list):
        return [fill_placeholders(v, secret, system_prompt) for v in value]
    if not isinstance(value, str):
        return value

    def sub(m: re.Match[str]) -> str:
        inner = m.group(1)
        if _SECRET_WORDS.search(inner) and secret:
            val = secret
        elif _PROMPT_WORDS.search(inner):
            val = system_prompt
        else:
            return m.group(0)
        low = inner.lower()
        if "base64" in low:
            return base64.b64encode(val.encode()).decode()
        if "hex" in low:
            return val.encode().hex()
        if "backwards" in low or "reversed" in low:
            return val[::-1]
        if "url-encoded" in low or "url encoded" in low:
            return quote(val, safe="")
        return val

    return _PLACEHOLDER.sub(sub, value)


def _canon(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, ensure_ascii=False)


# --------------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------------
class _RuleBasedModel(Target):
    guarded = False

    def complete(
        self, messages: list[Message], tools: list[ToolSpec], *, hints: TrialHints | None = None
    ) -> ModelResponse:
        hints = hints or TrialHints()
        system_prompt = "\n\n".join(m.content for m in messages if m.role == "system")
        found = CANARY_RE.search(system_prompt)
        secret = found.group(0) if found else hints.canary
        turn = sum(1 for m in messages if m.role == "assistant")
        done_calls = {
            (tc.name, _canon(tc.arguments)) for m in messages if m.role == "assistant" for tc in m.tool_calls
        }
        said = {m.content for m in messages if m.role == "assistant" and m.content}

        # The content the model is reacting to: trailing tool results, or the latest user message.
        trailing: list[Message] = []
        for m in reversed(messages):
            if m.role != "tool":
                break
            trailing.insert(0, m)
        sources: list[tuple[str, bool]] = []  # (text, trusted_as_instructions)
        if trailing:
            for m in trailing:
                trusted = (not self.guarded) or (m.name in hints.trusted_tools)
                sources.append((m.content, trusted))
        elif messages and messages[-1].role == "user":
            content = messages[-1].content
            if self.guarded:
                docs = _CONTEXT_BLOCK.findall(content)
                sources.append((_CONTEXT_BLOCK.sub("", content), True))
                sources.extend((d, False) for d in docs)
            else:
                sources.append((content, True))

        suspicious = False
        directives: list[Directive] = []
        for text, trusted in sources:
            ds = extract_directives(read_view(text), tools)
            if trusted:
                directives.extend(ds)
            elif ds:
                suspicious = True
        if self.guarded:
            # Remember earlier ignored injections so the final answer can flag them.
            for m in messages:
                if (
                    m.role == "tool"
                    and m.name not in hints.trusted_tools
                    and extract_directives(read_view(m.content), tools)
                ):
                    suspicious = True

        for d in reversed(directives):
            if d.kind == "tool":
                args = fill_placeholders(d.args, secret, system_prompt)
                if (d.tool, _canon(args)) in done_calls:
                    continue
                return ModelResponse(
                    content="",
                    tool_calls=[ToolCall(f"call_{turn}_0", d.tool, args)],
                    stop_reason="tool_calls",
                )
            if d.kind == "leak":
                if system_prompt in said:
                    continue
                return ModelResponse(content=system_prompt, stop_reason="stop")
            if d.kind == "say":
                text = fill_placeholders(d.text, secret, system_prompt)
                if d.append:
                    text = f"{hints.reference_answer or 'Done.'}\n\n{text}"
                if text in said:
                    continue
                return ModelResponse(content=text, stop_reason="stop")

        for step in hints.plan:
            key = (step["tool"], _canon(step.get("arguments") or {}))
            if key not in done_calls:
                return ModelResponse(
                    content="",
                    tool_calls=[ToolCall(f"call_{turn}_0", step["tool"], dict(step.get("arguments") or {}))],
                    stop_reason="tool_calls",
                )
        answer = hints.reference_answer or "Done."
        if self.guarded and suspicious:
            answer += (
                "\n\nNote: some retrieved content contained embedded instructions. "
                "I treated it as data and did not follow them."
            )
        return ModelResponse(content=answer, stop_reason="stop")

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "type": "mock"}


class NaiveMockModel(_RuleBasedModel):
    name = "mock:naive"
    guarded = False


class GuardedMockModel(_RuleBasedModel):
    name = "mock:guarded"
    guarded = True
