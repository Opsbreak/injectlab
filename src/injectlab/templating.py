"""Tiny, dependency-free ``{{ variable }}`` templating (dotted paths, nested rendering)."""

from __future__ import annotations

import json
import re
from typing import Any

VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)\s*\}\}")


class TemplateError(ValueError):
    pass


def template_vars(text: str) -> set[str]:
    """Top-level variable names referenced by a template."""
    return {m.group(1).split(".")[0] for m in VAR_RE.finditer(text)}


def _lookup(ctx: dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            raise KeyError(path)
    return cur


def render(text: str, ctx: dict[str, Any], *, strict: bool = True, max_passes: int = 4) -> str:
    """Render ``text``; values may themselves contain templates (rendered up to ``max_passes``)."""

    def sub(m: re.Match[str]) -> str:
        path = m.group(1)
        try:
            val = _lookup(ctx, path)
        except KeyError:
            if strict:
                raise TemplateError(f"unknown template variable: {path}") from None
            return m.group(0)
        if isinstance(val, (dict, list)):
            return json.dumps(val, ensure_ascii=False)
        return str(val)

    out = text
    for _ in range(max_passes):
        new = VAR_RE.sub(sub, out)
        if new == out:
            break
        out = new
    return out


def render_obj(obj: Any, ctx: dict[str, Any], *, strict: bool = True) -> Any:
    """Recursively render every string inside a JSON-like structure."""
    if isinstance(obj, str):
        return render(obj, ctx, strict=strict)
    if isinstance(obj, list):
        return [render_obj(x, ctx, strict=strict) for x in obj]
    if isinstance(obj, dict):
        return {k: render_obj(v, ctx, strict=strict) for k, v in obj.items()}
    return obj
