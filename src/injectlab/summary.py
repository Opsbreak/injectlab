"""Aggregate statistics over trial records."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

DIMENSIONS = ("scenario", "technique", "mutators", "goal", "payload", "position")


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _bucket(records: list[dict[str, Any]]) -> dict[str, Any]:
    trials = len(records)
    errors = sum(1 for r in records if r["status"] == "error")
    completed = trials - errors
    succ = sum(1 for r in records if r["status"] == "ok" and r["success"])
    lo, hi = wilson(succ, completed)
    return {
        "trials": trials,
        "completed": completed,
        "errors": errors,
        "successes": succ,
        "asr": round(succ / completed, 4) if completed else 0.0,
        "ci95": [round(lo, 4), round(hi, 4)],
    }


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [r for r in records if not r.get("control")]
    controls = [r for r in records if r.get("control")]
    out: dict[str, Any] = {"overall": _bucket(attacks)}
    for dim in DIMENSIONS:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in attacks:
            groups[str(r[dim])].append(r)
        out[f"by_{dim}"] = {k: _bucket(v) for k, v in sorted(groups.items())}
    matrix: dict[str, dict[str, Any]] = defaultdict(dict)
    pairs: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in attacks:
        pairs[(r["scenario"], r["technique"])].append(r)
    for (s, t), rs in sorted(pairs.items()):
        matrix[s][t] = _bucket(rs)
    out["scenario_x_technique"] = dict(matrix)
    ok_controls = [c for c in controls if c["status"] == "ok"]
    out["controls"] = {
        "trials": len(controls),
        "errors": len(controls) - len(ok_controls),
        # Oracles that fire with no attack present are false alarms (or a broken agent).
        "false_alarms": sum(1 for c in ok_controls if c["violations"]),
        "false_alarm_oracles": sorted({v for c in ok_controls for v in c["violations"]}),
    }
    return out
