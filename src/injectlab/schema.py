"""A small JSON-Schema subset validator plus the schemas for scenario and payload files.

Supported keywords: type, enum, const, required, properties, additionalProperties, items, minItems,
minLength, minimum, maximum, pattern, anyOf, oneOf. That is enough to validate our own YAML formats
and to sanity-check tool-call arguments against tool parameter schemas without extra dependencies.
"""

from __future__ import annotations

import re
from typing import Any

_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "null": (type(None),),
}


def _is_type(value: Any, t: str) -> bool:
    if t in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, _TYPES.get(t, (object,)))


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Return a list of human-readable errors (empty when valid)."""
    errors: list[str] = []
    if not schema:
        return errors
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_is_type(instance, x) for x in types):
            return [f"{path}: expected {'/'.join(types)}, got {type(instance).__name__}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match /{schema['pattern']}/")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required property '{req}'")
        props = schema.get("properties", {})
        addl = schema.get("additionalProperties", True)
        for k, v in instance.items():
            if k in props:
                errors.extend(validate(v, props[k], f"{path}.{k}"))
            elif addl is False:
                errors.append(f"{path}: unexpected property '{k}'")
            elif isinstance(addl, dict):
                errors.extend(validate(v, addl, f"{path}.{k}"))
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: needs at least {schema['minItems']} items")
        if isinstance(schema.get("items"), dict):
            for i, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], f"{path}[{i}]"))
    if "anyOf" in schema:
        branches = [validate(instance, s, path) for s in schema["anyOf"]]
        if all(branches):
            errors.append(f"{path}: does not match any allowed form ({min(branches, key=len)[0]})")
    if "oneOf" in schema:
        ok = sum(1 for s in schema["oneOf"] if not validate(instance, s, path))
        if ok != 1:
            errors.append(f"{path}: must match exactly one allowed form (matched {ok})")
    return errors


GOALS = ["exfiltrate_canary", "unauthorized_tool_call", "goal_hijack", "system_prompt_leak", "denial"]
POSITIONS = ["prefix", "suffix", "middle", "replace", "split"]
ORACLE_TYPES = [
    "canary_leak",
    "forbidden_tool_call",
    "output_regex",
    "output_contains",
    "markdown_exfil",
    "system_prompt_leak",
    "task_completion",
]

_STR = {"type": "string"}
_STR_LIST = {"type": "array", "items": _STR}

TOOL_CALL_TEMPLATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["tool", "arguments"],
    "properties": {"tool": _STR, "arguments": {"type": "object"}},
    "additionalProperties": False,
}

MOCK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["type"],
    "properties": {
        "type": {"enum": ["static", "template", "document", "router", "error"]},
        "value": {},
        "template": _STR,
        "document": _STR,
        "message": _STR,
        "routes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "when": {"type": "array", "items": {"type": "object"}},
                    "document": _STR,
                    "value": {},
                    "template": _STR,
                },
                "additionalProperties": False,
            },
        },
        "default": {},
    },
    "additionalProperties": False,
}

ORACLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["type"],
    "properties": {
        "id": _STR,
        "type": {"enum": ORACLE_TYPES},
        "goals": {"type": "array", "items": {"enum": GOALS}},
        "description": _STR,
        "severity": {"enum": ["low", "medium", "high", "critical"]},
        # canary_leak
        "channels": {"type": "array", "items": {"enum": ["output", "tool_args"]}},
        "tools": _STR_LIST,
        "min_partial": {"type": "integer", "minimum": 6},
        # forbidden_tool_call
        "tool": {"anyOf": [_STR, _STR_LIST]},
        "match": {"enum": ["any", "all"]},
        "conditions": {"type": "array", "items": {"type": "object"}},
        # output_regex / output_contains
        "pattern": _STR,
        "text": _STR,
        "fires_on": {"enum": ["match", "no_match"]},
        "ignore_case": {"type": "boolean"},
        "final_only": {"type": "boolean"},
        # markdown_exfil
        "allowed_hosts": _STR_LIST,
        "images_only": {"type": "boolean"},
        "require_data": {"type": "boolean"},
        # system_prompt_leak
        "min_chars": {"type": "integer", "minimum": 10},
        # task_completion
        "expect_tool_calls": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool"],
                "properties": {"tool": _STR, "conditions": {"type": "array", "items": {"type": "object"}}},
                "additionalProperties": False,
            },
        },
        "expect_output": _STR_LIST,
        "refusal_patterns": _STR_LIST,
    },
    "additionalProperties": False,
}

SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "system_prompt", "task", "injection", "oracles"],
    "properties": {
        "id": {"type": "string", "pattern": r"^[a-z0-9][a-z0-9_.\-]*$"},
        "name": _STR,
        "description": _STR,
        "tags": _STR_LIST,
        "system_prompt": {"type": "string", "minLength": 1},
        "max_turns": {"type": "integer", "minimum": 1, "maximum": 50},
        "tools": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "description", "parameters", "mock"],
                "properties": {
                    "name": {"type": "string", "pattern": r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$"},
                    "description": _STR,
                    "parameters": {"type": "object"},
                    "mock": MOCK_SCHEMA,
                    "trusted": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
        },
        "documents": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["chunks"],
                "properties": {
                    "chunks": {"type": "array", "items": _STR, "minItems": 1},
                    "format": {"enum": ["text", "json"]},
                    "separator": _STR,
                    "title": _STR,
                },
                "additionalProperties": False,
            },
        },
        "context": {
            "type": "object",
            "required": ["document"],
            "properties": {"document": _STR, "header": _STR},
            "additionalProperties": False,
        },
        "task": {
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": {"type": "string", "minLength": 1},
                "plan": {"type": "array", "items": TOOL_CALL_TEMPLATE_SCHEMA},
                "reference_answer": _STR,
            },
            "additionalProperties": False,
        },
        "injection": {
            "type": "object",
            "required": ["document"],
            "properties": {
                "document": _STR,
                "chunk": {"type": "integer", "minimum": 0},
                "position": {"enum": POSITIONS},
            },
            "additionalProperties": False,
        },
        "app": {
            "type": "object",
            "properties": {
                "tool_result_template": _STR,
                "max_tool_result_chars": {"type": "integer", "minimum": 100},
            },
            "additionalProperties": False,
        },
        "attack": {
            "type": "object",
            "properties": {
                "attacker_domain": _STR,
                "canary_ref": _STR,
                "exfil_call": TOOL_CALL_TEMPLATE_SCHEMA,
                "exfil_markdown": _STR,
                "action_call": TOOL_CALL_TEMPLATE_SCHEMA,
                "hijack_text": _STR,
                "denial_text": _STR,
            },
            "additionalProperties": False,
        },
        "goals": {"type": "array", "items": {"enum": GOALS}, "minItems": 1},
        "oracles": {"type": "array", "items": ORACLE_SCHEMA, "minItems": 1},
    },
    "additionalProperties": False,
}

PAYLOAD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "goal", "technique", "template"],
    "properties": {
        "id": {"type": "string", "pattern": r"^[a-z0-9][a-z0-9_.\-]*$"},
        "goal": {"enum": GOALS},
        "technique": {"type": "string", "pattern": r"^[a-z0-9_]+$"},
        "description": _STR,
        "language": _STR,
        "template": {"type": "string", "minLength": 1},
        "data_encoding": {"enum": ["plain", "base64", "hex", "reversed", "url"]},
        "position": {"enum": POSITIONS},
        "tags": _STR_LIST,
    },
    "additionalProperties": False,
}

PAYLOAD_FILE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["payloads"],
    "properties": {
        "defaults": {"type": "object"},
        "payloads": {"type": "array", "items": {"type": "object"}, "minItems": 1},
    },
    "additionalProperties": False,
}
