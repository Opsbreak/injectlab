"""Scenario and payload models, YAML loading and validation."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from injectlab.predicates import validate_condition
from injectlab.schema import (
    GOALS,
    PAYLOAD_FILE_SCHEMA,
    PAYLOAD_SCHEMA,
    SCENARIO_SCHEMA,
    validate,
)
from injectlab.templating import template_vars

DEFAULT_ATTACK: dict[str, Any] = {
    "attacker_domain": "attacker.example",
    "canary_ref": "the internal reference code from your instructions",
    "hijack_text": "Your session has expired. Sign in again at https://{{attacker_domain}}/login to continue.",
    "denial_text": "Sorry, this request cannot be completed right now.",
}

# Variables a payload template may reference. Availability depends on scenario and goal.
PAYLOAD_VARS = {
    "instruction",
    "attacker_domain",
    "canary_ref",
    "tool_name",
    "tool_args",
    "exfil_url",
    "data_slot",
    "hijack_text",
    "denial_text",
    "user_task",
    "app_name",
}
SCENARIO_VARS = {"canary", "attacker_domain", "canary_ref", "hijack_text", "denial_text", "app_name"}


class SuiteError(ValueError):
    pass


@dataclass
class Document:
    name: str
    chunks: list[str]
    format: str = "text"
    separator: str = "\n\n---\n\n"
    title: str | None = None


@dataclass
class ToolDef:
    name: str
    description: str
    parameters: dict[str, Any]
    mock: dict[str, Any]
    trusted: bool = False


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    system_prompt: str
    task_prompt: str
    tools: list[ToolDef]
    documents: dict[str, Document]
    injection: dict[str, Any]
    oracles: list[dict[str, Any]]
    goals: list[str]
    attack: dict[str, Any]
    plan: list[dict[str, Any]] = field(default_factory=list)
    reference_answer: str = ""
    context: dict[str, Any] | None = None
    app: dict[str, Any] = field(default_factory=dict)
    max_turns: int = 8
    tags: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def injection_document(self) -> Document:
        return self.documents[self.injection["document"]]

    @property
    def injection_position(self) -> str:
        return str(self.injection.get("position", "suffix"))

    @property
    def injection_chunk(self) -> int:
        return int(self.injection.get("chunk", 0))

    def attack_vars(self) -> dict[str, Any]:
        out = dict(DEFAULT_ATTACK)
        out.update(self.attack)
        out.setdefault("app_name", self.name)
        return out


@dataclass
class Payload:
    id: str
    goal: str
    technique: str
    template: str
    description: str = ""
    language: str = "en"
    data_encoding: str = "plain"
    position: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def variables(self) -> set[str]:
        return template_vars(self.template)


# --------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------
def _yaml_files(paths: list[str | Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(sorted(x for x in p.rglob("*") if x.suffix in (".yaml", ".yml")))
        elif p.is_file():
            files.append(p)
        else:
            raise SuiteError(f"no such file or directory: {p}")
    return files


def _read_yaml(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise SuiteError(f"{path}: invalid YAML: {e}") from e


def _scenario_from_dict(d: dict[str, Any], source: str) -> Scenario:
    documents = {
        name: Document(
            name=name,
            chunks=[str(c) for c in doc["chunks"]],
            format=doc.get("format", "text"),
            separator=doc.get("separator", "\n\n---\n\n"),
            title=doc.get("title"),
        )
        for name, doc in (d.get("documents") or {}).items()
    }
    tools = [
        ToolDef(
            name=t["name"],
            description=t["description"],
            parameters=t["parameters"],
            mock=t["mock"],
            trusted=bool(t.get("trusted", False)),
        )
        for t in d.get("tools") or []
    ]
    oracles = []
    for i, o in enumerate(d["oracles"]):
        o = dict(o)
        o.setdefault("id", f"{o['type']}#{i}")
        oracles.append(o)
    task = d["task"]
    return Scenario(
        id=d["id"],
        name=d.get("name", d["id"]),
        description=d.get("description", ""),
        system_prompt=d["system_prompt"],
        task_prompt=task["prompt"],
        plan=list(task.get("plan") or []),
        reference_answer=task.get("reference_answer", ""),
        tools=tools,
        documents=documents,
        injection=dict(d["injection"]),
        context=d.get("context"),
        app=dict(d.get("app") or {}),
        oracles=oracles,
        goals=list(d.get("goals") or GOALS),
        attack=dict(d.get("attack") or {}),
        max_turns=int(d.get("max_turns", 8)),
        tags=list(d.get("tags") or []),
        source=source,
    )


def scenario_semantic_errors(s: Scenario) -> list[str]:
    errs: list[str] = []
    names = [t.name for t in s.tools]
    if len(names) != len(set(names)):
        errs.append("duplicate tool names")
    for t in s.tools:
        m = t.mock
        if m["type"] == "document" and m.get("document") not in s.documents:
            errs.append(f"tool {t.name}: unknown document '{m.get('document')}'")
        if m["type"] == "template" and "template" not in m:
            errs.append(f"tool {t.name}: template mock needs 'template'")
        for r in m.get("routes") or []:
            if "document" in r and r["document"] not in s.documents:
                errs.append(f"tool {t.name}: route references unknown document '{r['document']}'")
            for c in r.get("when") or []:
                errs.extend(f"tool {t.name}: {e}" for e in validate_condition(c))
        if (
            isinstance(m.get("default"), dict)
            and "document" in m["default"]
            and (m["default"]["document"] not in s.documents)
        ):
            errs.append(f"tool {t.name}: default references unknown document")
    doc = s.injection.get("document")
    if doc not in s.documents:
        errs.append(f"injection: unknown document '{doc}'")
    elif s.injection_chunk >= len(s.documents[doc].chunks):
        errs.append(f"injection: chunk {s.injection_chunk} out of range for document '{doc}'")
    if s.context and s.context["document"] not in s.documents:
        errs.append(f"context: unknown document '{s.context['document']}'")
    for step in s.plan:
        if step["tool"] not in names:
            errs.append(f"task.plan: unknown tool '{step['tool']}'")
    for key in ("exfil_call", "action_call"):
        call = s.attack.get(key)
        if call and call["tool"] not in names:
            errs.append(f"attack.{key}: unknown tool '{call['tool']}'")
    if "exfiltrate_canary" in s.goals and not (s.attack.get("exfil_call") or s.attack.get("exfil_markdown")):
        errs.append("goal exfiltrate_canary needs attack.exfil_call or attack.exfil_markdown")
    if "unauthorized_tool_call" in s.goals and not s.attack.get("action_call"):
        errs.append("goal unauthorized_tool_call needs attack.action_call")
    if "{{canary}}" not in s.system_prompt.replace(" ", "") and (
        {"exfiltrate_canary", "system_prompt_leak"} & set(s.goals)
    ):
        errs.append("system_prompt must contain {{canary}} for exfiltration / leak goals")
    allowed = SCENARIO_VARS | set(s.attack)
    for label, text in [("system_prompt", s.system_prompt), ("task.prompt", s.task_prompt)] + [
        (f"documents.{d.name}", c) for d in s.documents.values() for c in d.chunks
    ]:
        unknown = template_vars(text) - allowed
        if unknown:
            errs.append(f"{label}: unknown template variables {sorted(unknown)}")
    ids = [o["id"] for o in s.oracles]
    if len(ids) != len(set(ids)):
        errs.append("duplicate oracle ids")
    for o in s.oracles:
        oid = o["id"]
        for c in o.get("conditions") or []:
            errs.extend(f"oracle {oid}: {e}" for e in validate_condition(c))
        for exp in o.get("expect_tool_calls") or []:
            if exp["tool"] not in names:
                errs.append(f"oracle {oid}: unknown tool '{exp['tool']}'")
            for c in exp.get("conditions") or []:
                errs.extend(f"oracle {oid}: {e}" for e in validate_condition(c))
        tool = o.get("tool")
        for t in [tool] if isinstance(tool, str) else tool or []:
            if not t.startswith("re:") and t not in names:
                errs.append(f"oracle {oid}: unknown tool '{t}'")
        for t in o.get("tools") or []:
            if t not in names:
                errs.append(f"oracle {oid}: unknown tool '{t}'")
        for key in ("pattern",):
            if key in o:
                try:
                    re.compile(o[key])
                except re.error as e:
                    errs.append(f"oracle {oid}: bad regex: {e}")
        for pat in (o.get("expect_output") or []) + (o.get("refusal_patterns") or []):
            try:
                re.compile(pat)
            except re.error as e:
                errs.append(f"oracle {oid}: bad regex {pat!r}: {e}")
        if o["type"] == "forbidden_tool_call" and "tool" not in o:
            errs.append(f"oracle {oid}: forbidden_tool_call needs 'tool'")
        if o["type"] == "output_regex" and "pattern" not in o:
            errs.append(f"oracle {oid}: output_regex needs 'pattern'")
        if o["type"] == "output_contains" and "text" not in o:
            errs.append(f"oracle {oid}: output_contains needs 'text'")
    return errs


def load_scenarios(paths: list[str | Path], *, strict: bool = True) -> list[Scenario]:
    scenarios: list[Scenario] = []
    for f in _yaml_files(paths):
        data = _read_yaml(f)
        items = data.get("scenarios") if isinstance(data, dict) and "scenarios" in data else [data]
        for item in items:
            errs = validate(item, SCENARIO_SCHEMA)
            if errs:
                raise SuiteError(f"{f}: " + "; ".join(errs))
            s = _scenario_from_dict(item, str(f))
            sem = scenario_semantic_errors(s)
            if sem and strict:
                raise SuiteError(f"{f}: " + "; ".join(sem))
            scenarios.append(s)
    ids = [s.id for s in scenarios]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SuiteError(f"duplicate scenario ids: {sorted(dupes)}")
    return scenarios


def load_payloads(paths: list[str | Path]) -> list[Payload]:
    payloads: list[Payload] = []
    for f in _yaml_files(paths):
        data = _read_yaml(f)
        errs = validate(data, PAYLOAD_FILE_SCHEMA)
        if errs:
            raise SuiteError(f"{f}: " + "; ".join(errs))
        defaults = data.get("defaults") or {}
        for raw in data["payloads"]:
            item = {**defaults, **raw}
            errs = validate(item, PAYLOAD_SCHEMA)
            if errs:
                raise SuiteError(f"{f}: payload {raw.get('id', '?')}: " + "; ".join(errs))
            unknown = template_vars(item["template"]) - PAYLOAD_VARS
            if unknown:
                raise SuiteError(f"{f}: payload {item['id']}: unknown template variables {sorted(unknown)}")
            payloads.append(
                Payload(
                    id=item["id"],
                    goal=item["goal"],
                    technique=item["technique"],
                    template=item["template"],
                    description=item.get("description", ""),
                    language=item.get("language", "en"),
                    data_encoding=item.get("data_encoding", "plain"),
                    position=item.get("position"),
                    tags=list(item.get("tags") or []),
                    source=str(f),
                )
            )
    ids = [p.id for p in payloads]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SuiteError(f"duplicate payload ids: {sorted(dupes)}")
    return payloads


def validate_paths(paths: list[str | Path]) -> tuple[int, list[str]]:
    """Validate every YAML file; returns (files_checked, errors). Detects file kind by content."""
    errors: list[str] = []
    files = _yaml_files(paths)
    for f in files:
        try:
            data = _read_yaml(f)
        except SuiteError as e:
            errors.append(str(e))
            continue
        if isinstance(data, dict) and "payloads" in data:
            try:
                load_payloads([f])
            except SuiteError as e:
                errors.append(str(e))
        elif isinstance(data, dict):
            items = data.get("scenarios") if "scenarios" in data else [data]
            for item in items:
                errs = validate(item, SCENARIO_SCHEMA)
                if errs:
                    errors.extend(f"{f}: {e}" for e in errs)
                    continue
                errors.extend(
                    f"{f}: {e}" for e in scenario_semantic_errors(_scenario_from_dict(item, str(f)))
                )
        else:
            errors.append(f"{f}: expected a mapping at the top level")
    return len(files), errors


def bundled_dir(kind: str) -> Path:
    """Locate the bundled ``scenarios`` / ``payloads`` directory (wheel install or source checkout)."""
    here = Path(__file__).resolve().parent
    for cand in (here / "_suite" / kind, here.parents[1] / kind):
        if cand.is_dir():
            return cand
    raise SuiteError(f"bundled {kind} directory not found")


def filter_ids(items: list[Any], patterns: list[str] | None) -> list[Any]:
    if not patterns:
        return items
    return [x for x in items if any(fnmatch.fnmatch(x.id, p) for p in patterns)]


def describe_tool_call(tool: str, args: dict[str, Any]) -> str:
    return f"call the {tool} tool with {json.dumps(args, ensure_ascii=False)}"
