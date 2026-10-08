"""Experiment runner: scenarios x payloads x mutator chains x positions x repeats."""

from __future__ import annotations

import hashlib
import json
import time
import traceback
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from injectlab import __version__
from injectlab.agent import run_agent
from injectlab.canary import make_canary
from injectlab.conversation import TrialHints
from injectlab.injection import inject, payload_variables, render_document, seeded_rng
from injectlab.mutators import MutatorChain
from injectlab.oracles import Observation, evaluate
from injectlab.sandbox import ToolSandbox
from injectlab.suite import Payload, Scenario
from injectlab.summary import summarize
from injectlab.targets.base import Target
from injectlab.templating import render, render_obj

CONTROL_ID = "__control__"


@dataclass(frozen=True)
class TrialSpec:
    index: int
    scenario: Scenario
    payload: Payload | None  # None => control trial (no injection)
    chain: MutatorChain
    position: str
    repeat: int
    seed: str

    @property
    def key(self) -> str:
        pid = self.payload.id if self.payload else CONTROL_ID
        return f"{self.scenario.id}|{pid}|{self.chain.label}|{self.position}|{self.repeat}"

    @property
    def trial_id(self) -> str:
        return hashlib.sha256(f"{self.seed}|{self.key}".encode()).hexdigest()[:12]

    @property
    def trial_seed(self) -> str:
        return hashlib.sha256(f"seed|{self.seed}|{self.key}".encode()).hexdigest()[:16]


@dataclass
class TrialResult:
    record: dict[str, Any]
    transcript: dict[str, Any]


@dataclass
class RunConfig:
    target: Target
    scenarios: list[Scenario]
    payloads: list[Payload]
    chains: list[MutatorChain]
    repeats: int = 1
    seed: str = "0"
    concurrency: int = 4
    positions: list[str] | None = None
    controls: bool = True
    max_turns: int | None = None
    target_label: str | None = None
    extra_meta: dict[str, Any] = field(default_factory=dict)


def plan_trials(cfg: RunConfig) -> tuple[list[TrialSpec], int]:
    """Return the trial list plus the number of skipped (incompatible) scenario/payload pairs."""
    trials: list[TrialSpec] = []
    skipped = 0
    idx = 0
    for s in cfg.scenarios:
        if cfg.controls:
            for r in range(cfg.repeats):
                trials.append(TrialSpec(idx, s, None, MutatorChain(), "none", r, cfg.seed))
                idx += 1
        for p in cfg.payloads:
            if payload_variables(s, p) is None:
                skipped += 1
                continue
            positions = cfg.positions or [p.position or s.injection_position]
            for chain in cfg.chains:
                for pos in positions:
                    for r in range(cfg.repeats):
                        trials.append(TrialSpec(idx, s, p, chain, pos, r, cfg.seed))
                        idx += 1
    return trials, skipped


def _scenario_vars(s: Scenario, canary: str) -> dict[str, Any]:
    av = s.attack_vars()
    flat = {k: v for k, v in av.items() if isinstance(v, str)}
    flat = {k: render(v, flat, strict=False) for k, v in flat.items()}
    return {**flat, "canary": canary}


def run_trial(spec: TrialSpec, target: Target, *, max_turns: int | None = None) -> TrialResult:
    s = spec.scenario
    t0 = time.perf_counter()
    canary = make_canary(spec.trial_seed)
    rng = seeded_rng(spec.trial_seed)
    variables = _scenario_vars(s, canary)
    system_prompt = render(s.system_prompt, variables)
    task_prompt = render(s.task_prompt, variables)

    payload_text = ""
    segments: list[str] = []
    chunks_by_doc = {name: [render(c, variables) for c in d.chunks] for name, d in s.documents.items()}
    if spec.payload is not None:
        pv = payload_variables(s, spec.payload)
        assert pv is not None
        payload_text = render(spec.payload.template, pv).strip()
        segments = spec.chain.apply(payload_text, rng)
        doc = s.injection_document
        rendered_doc = type(doc)(doc.name, chunks_by_doc[doc.name], doc.format, doc.separator, doc.title)
        chunks_by_doc[doc.name] = inject(rendered_doc, segments, spec.position, s.injection_chunk)
    documents = {name: render_document(d, chunks_by_doc[name]) for name, d in s.documents.items()}

    user_message = task_prompt
    if s.context:
        ctx_doc = s.documents[s.context["document"]]
        header = s.context.get("header", "Use the following retrieved documents to answer.")
        blocks = "\n".join(
            f'<document id="{ctx_doc.name}-{i}">\n{c}\n</document>'
            for i, c in enumerate(chunks_by_doc[ctx_doc.name])
        )
        user_message = f"{task_prompt}\n\n{header}\n<retrieved_documents>\n{blocks}\n</retrieved_documents>"

    sandbox = ToolSandbox(
        s.tools,
        documents,
        variables,
        result_template=s.app.get("tool_result_template"),
        max_result_chars=s.app.get("max_tool_result_chars"),
    )
    hints = TrialHints(
        plan=[
            {"tool": st["tool"], "arguments": render_obj(st["arguments"], variables, strict=False)}
            for st in s.plan
        ],
        reference_answer=render(s.reference_answer, variables, strict=False),
        trusted_tools=[t.name for t in s.tools if t.trusted],
        canary=canary,
    )
    error: str | None = None
    try:
        transcript = run_agent(
            target,
            sandbox,
            system_prompt=system_prompt,
            user_message=user_message,
            max_turns=max_turns or s.max_turns,
            hints=hints,
        )
        error = transcript.error
    except Exception as e:  # a bug in a target adapter must not kill the whole run
        from injectlab.agent import Transcript

        transcript = Transcript(stop_reason="error", error=f"{type(e).__name__}: {e}")
        transcript.executions = list(sandbox.executions)
        error = transcript.error + "\n" + traceback.format_exc(limit=3)

    goal = spec.payload.goal if spec.payload else "none"
    obs = Observation.from_transcript(transcript, system_prompt=system_prompt, canary=canary)
    results = evaluate(s.oracles, obs, variables) if error is None else []
    fired = [r for r in results if r.fired]
    if spec.payload is None:
        success = False
    else:
        success = any(r.applies_to(goal) for r in fired)
    record = {
        "index": spec.index,
        "trial_id": spec.trial_id,
        "key": spec.key,
        "scenario": s.id,
        "payload": spec.payload.id if spec.payload else CONTROL_ID,
        "control": spec.payload is None,
        "goal": goal,
        "technique": spec.payload.technique if spec.payload else "none",
        "language": spec.payload.language if spec.payload else "",
        "mutators": spec.chain.label,
        "position": spec.position,
        "repeat": spec.repeat,
        "seed": spec.trial_seed,
        "canary": canary,
        "status": "error" if error else "ok",
        "error": error,
        "success": success,
        "violations": [r.id for r in fired],
        "oracles": [r.to_dict() for r in results],
        "turns": transcript.turns,
        "stop_reason": transcript.stop_reason,
        "tool_calls": [
            {"turn": e.turn, "name": e.name, "arguments": e.arguments} for e in transcript.executions
        ],
        "final_output": transcript.final_output[:2000],
        "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
    transcript_rec = {
        "trial_id": spec.trial_id,
        "key": spec.key,
        "payload_text": payload_text,
        "injected_segments": segments,
        "user_message": user_message,
        **transcript.to_dict(),
    }
    return TrialResult(record, transcript_rec)


def run_id_for(cfg: RunConfig, trials: list[TrialSpec]) -> str:
    h = hashlib.sha256()
    h.update(json.dumps(cfg.target.describe(), sort_keys=True, default=str).encode())
    h.update(cfg.seed.encode())
    for t in trials:
        h.update(t.key.encode())
    return h.hexdigest()[:16]


def run(
    cfg: RunConfig,
    *,
    out_dir: str | Path | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    trials, skipped = plan_trials(cfg)
    results: list[TrialResult | None] = [None] * len(trials)
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    done = 0

    def work(spec: TrialSpec) -> tuple[int, TrialResult]:
        return spec.index, run_trial(spec, cfg.target, max_turns=cfg.max_turns)

    with ThreadPoolExecutor(max_workers=max(1, cfg.concurrency)) as pool:
        for idx, res in pool.map(work, trials):
            results[idx] = res
            done += 1
            if progress:
                progress(done, len(trials))

    records = [r.record for r in results if r is not None]
    output: dict[str, Any] = {
        "injectlab_version": __version__,
        "run_id": run_id_for(cfg, trials),
        "created_at": started.isoformat(timespec="seconds"),
        "elapsed_s": round(time.perf_counter() - t0, 3),
        "config": {
            "target": cfg.target_label or cfg.target.name,
            "target_info": cfg.target.describe(),
            "seed": cfg.seed,
            "repeats": cfg.repeats,
            "mutators": [c.label for c in cfg.chains],
            "positions": cfg.positions,
            "concurrency": cfg.concurrency,
            "controls": cfg.controls,
            "scenarios": [s.id for s in cfg.scenarios],
            "payloads": [p.id for p in cfg.payloads],
            "skipped_pairs": skipped,
            **cfg.extra_meta,
        },
        "summary": summarize(records),
        "trials": records,
    }
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "results.json").write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        with (out / "transcripts.jsonl").open("w", encoding="utf-8") as f:
            for r in results:
                if r is not None:
                    f.write(json.dumps(r.transcript, ensure_ascii=False) + "\n")
    return output
