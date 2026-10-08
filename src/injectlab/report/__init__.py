"""Report writers: self-contained HTML, JUnit XML, and baseline comparison."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def resolve_results_path(path: str | Path) -> Path:
    p = Path(path)
    if p.is_dir():
        p = p / "results.json"
    if not p.is_file():
        raise FileNotFoundError(f"results file not found: {p}")
    return p


def load_results(path: str | Path) -> dict[str, Any]:
    p = resolve_results_path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if "trials" not in data or "summary" not in data:
        raise ValueError(f"{p} is not an injectlab results file")
    return data


def load_transcripts(results_path: str | Path) -> dict[str, dict[str, Any]]:
    p = resolve_results_path(results_path).parent / "transcripts.jsonl"
    out: dict[str, dict[str, Any]] = {}
    if not p.is_file():
        return out
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rec = json.loads(line)
                out[rec["trial_id"]] = rec
    return out
