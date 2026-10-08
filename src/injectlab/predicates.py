"""Argument predicates used by forbidden-tool-call oracles, task-completion checks and mock routers.

A condition is a mapping with an ``arg`` (dotted path into the tool arguments) and one operator::

    {arg: to, not_endswith: ["@acme.example"]}
    {arg: url, host_not_in: ["docs.acme.example"]}
    {arg: amount, gt: 5000}
    {all: [...]} / {any: [...]} / {not: {...}}

If the addressed value is a list, the condition holds when ANY element satisfies the operator. String
comparisons are case-insensitive unless ``case_sensitive: true``. A missing argument never satisfies
an operator (use ``exists: false`` to test for absence).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "startswith",
    "endswith",
    "not_endswith",
    "matches",
    "not_matches",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "host_in",
    "host_not_in",
    "exists",
    "contains_canary",
}


class PredicateError(ValueError):
    pass


_MISSING = object()


def _resolve(args: Any, path: str) -> Any:
    cur = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def _flatten(v: Any) -> list[Any]:
    if isinstance(v, list):
        out: list[Any] = []
        for x in v:
            out.extend(_flatten(x))
        return out
    return [v]


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def url_host(value: str) -> str:
    # Deliberately NOT folding homoglyphs: 'аcme.example' (Cyrillic a) is a different host.
    v = str(value).strip()
    if "://" not in v:
        v = "http://" + v
    try:
        host = urlsplit(v).hostname or ""
    except ValueError:
        host = ""
    return host.lower().rstrip(".")


def host_matches(host: str, allowed: list[str]) -> bool:
    host = host.lower()
    for a in allowed:
        a = str(a).lower().lstrip(".")
        if host == a or host.endswith("." + a):
            return True
    return False


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.replace(",", "").replace("$", "").strip())
        except ValueError:
            return None
    return None


def check_condition(
    cond: dict[str, Any],
    args: dict[str, Any],
    *,
    canary_check: Callable[[str], bool] | None = None,
) -> bool:
    if "all" in cond:
        return all(check_condition(c, args, canary_check=canary_check) for c in cond["all"])
    if "any" in cond:
        return any(check_condition(c, args, canary_check=canary_check) for c in cond["any"])
    if "not" in cond:
        return not check_condition(cond["not"], args, canary_check=canary_check)
    if "arg" not in cond:
        raise PredicateError(f"condition needs 'arg': {cond}")
    ops = [k for k in cond if k in OPERATORS]
    if len(ops) != 1:
        raise PredicateError(f"condition needs exactly one operator from {sorted(OPERATORS)}: {cond}")
    op = ops[0]
    expected = cond[op]
    cs = bool(cond.get("case_sensitive", False))
    raw = _resolve(args, str(cond["arg"]))
    if op == "exists":
        return (raw is not _MISSING) == bool(expected)
    if raw is _MISSING:
        return False
    values = _flatten(raw)

    def norm(x: Any) -> str:
        s = x if isinstance(x, str) else str(x)
        return s if cs else s.lower()

    def one(v: Any) -> bool:
        if op in ("equals", "not_equals"):
            eq = (
                norm(v) == norm(expected)
                if isinstance(v, str) or isinstance(expected, str)
                else v == expected
            )
            return eq if op == "equals" else not eq
        if op in ("contains", "not_contains"):
            hit = any(norm(e) in norm(v) for e in _as_list(expected))
            return hit if op == "contains" else not hit
        if op == "startswith":
            return any(norm(v).startswith(norm(e)) for e in _as_list(expected))
        if op in ("endswith", "not_endswith"):
            hit = any(norm(v).strip().endswith(norm(e)) for e in _as_list(expected))
            return hit if op == "endswith" else not hit
        if op in ("matches", "not_matches"):
            hit = re.search(str(expected), str(v), 0 if cs else re.IGNORECASE) is not None
            return hit if op == "matches" else not hit
        if op in ("in", "not_in"):
            hit = norm(v) in {norm(e) for e in _as_list(expected)}
            return hit if op == "in" else not hit
        if op in ("gt", "gte", "lt", "lte"):
            n, e = _num(v), _num(expected)
            if n is None or e is None:
                return False
            return {"gt": n > e, "gte": n >= e, "lt": n < e, "lte": n <= e}[op]
        if op in ("host_in", "host_not_in"):
            host = url_host(str(v))
            if not host:
                return False
            hit = host_matches(host, _as_list(expected))
            return hit if op == "host_in" else not hit
        if op == "contains_canary":
            if canary_check is None:
                return False
            return canary_check(str(v)) == bool(expected)
        raise PredicateError(op)  # pragma: no cover

    return any(one(v) for v in values)


def check_conditions(
    conds: list[dict[str, Any]],
    args: dict[str, Any],
    *,
    match: str = "all",
    canary_check: Callable[[str], bool] | None = None,
) -> bool:
    if not conds:
        return True
    results = (check_condition(c, args, canary_check=canary_check) for c in conds)
    return any(results) if match == "any" else all(results)


def validate_condition(cond: Any) -> list[str]:
    if not isinstance(cond, dict):
        return [f"condition must be a mapping: {cond!r}"]
    if "all" in cond or "any" in cond:
        key = "all" if "all" in cond else "any"
        if not isinstance(cond[key], list):
            return [f"'{key}' must be a list"]
        return [e for c in cond[key] for e in validate_condition(c)]
    if "not" in cond:
        return validate_condition(cond["not"])
    errs = []
    if "arg" not in cond:
        errs.append(f"condition missing 'arg': {cond}")
    ops = [k for k in cond if k in OPERATORS]
    if len(ops) != 1:
        errs.append(f"condition must have exactly one operator: {cond}")
    unknown = set(cond) - OPERATORS - {"arg", "case_sensitive"}
    if unknown:
        errs.append(f"unknown keys in condition: {sorted(unknown)}")
    if ops and ops[0] in ("matches", "not_matches"):
        try:
            re.compile(str(cond[ops[0]]))
        except re.error as e:
            errs.append(f"bad regex {cond[ops[0]]!r}: {e}")
    return errs
