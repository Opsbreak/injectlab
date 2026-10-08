"""Command-line interface: run, report, compare, list, validate."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Any

from injectlab import __version__
from injectlab.mutators import REGISTRY, MutatorError, parse_chains
from injectlab.report import load_results
from injectlab.report.compare import compare, format_comparison
from injectlab.report.html import write_html_report
from injectlab.report.junit import write_junit
from injectlab.runner import RunConfig, plan_trials, run
from injectlab.schema import GOALS, POSITIONS
from injectlab.suite import SuiteError, bundled_dir, filter_ids, load_payloads, load_scenarios, validate_paths
from injectlab.targets import TARGET_KINDS, RateLimitedTarget, TargetError, make_target

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _csv(v: str | None) -> list[str] | None:
    if not v:
        return None
    return [x.strip() for x in v.split(",") if x.strip()]


def _paths(values: list[str] | None, kind: str) -> list[str | Path]:
    return list(values) if values else [bundled_dir(kind)]


def _print_summary(res: dict[str, Any], out: Any = None) -> None:
    out = out or sys.stdout
    s = res["summary"]
    ov = s["overall"]
    w = out.write
    w(f"\ninjectlab {res['injectlab_version']}  run {res['run_id']}  target {res['config']['target']}\n")
    w(
        f"trials: {ov['trials']}  completed: {ov['completed']}  errors: {ov['errors']}  "
        f"skipped pairs: {res['config'].get('skipped_pairs', 0)}\n"
    )
    w(
        f"ATTACK SUCCESS RATE: {ov['asr'] * 100:.1f}%  ({ov['successes']}/{ov['completed']}, "
        f"95% CI {ov['ci95'][0] * 100:.1f}-{ov['ci95'][1] * 100:.1f}%)\n"
    )
    c = s.get("controls", {})
    if c.get("trials"):
        w(f"benign controls: {c['trials']} run, {c['false_alarms']} false alarm(s)\n")

    def table(title: str, buckets: dict[str, Any]) -> None:
        w(f"\n{title}\n")
        for name, b in sorted(buckets.items(), key=lambda kv: (-kv[1]["asr"], kv[0])):
            bar = "#" * round(b["asr"] * 20)
            w(f"  {name:<32} {b['asr'] * 100:5.1f}%  {b['successes']:>4}/{b['completed']:<4} {bar}\n")

    table("by scenario", s["by_scenario"])
    table("by technique", s["by_technique"])
    table("by mutator chain", s["by_mutators"])
    table("by goal", s["by_goal"])


def cmd_run(args: argparse.Namespace) -> int:
    try:
        scenarios = filter_ids(load_scenarios(_paths(args.scenarios, "scenarios")), _csv(args.only_scenarios))
        payloads = filter_ids(load_payloads(_paths(args.payloads, "payloads")), _csv(args.only_payloads))
        chains = parse_chains(args.mutators, include_baseline=not args.no_baseline)
    except (SuiteError, MutatorError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    goals = _csv(args.goals)
    if goals:
        bad = set(goals) - set(GOALS)
        if bad:
            print(f"error: unknown goal(s) {sorted(bad)}; known: {GOALS}", file=sys.stderr)
            return EXIT_USAGE
        payloads = [p for p in payloads if p.goal in goals]
    techniques = _csv(args.techniques)
    if techniques:
        payloads = [p for p in payloads if p.technique in techniques]
    positions = _csv(args.positions)
    if positions and set(positions) - set(POSITIONS):
        print(f"error: unknown position(s); known: {POSITIONS}", file=sys.stderr)
        return EXIT_USAGE
    if not scenarios or not payloads:
        print("error: no scenarios or payloads selected", file=sys.stderr)
        return EXIT_USAGE
    try:
        target = make_target(args.target)
    except (TargetError, KeyError) as e:
        print(f"error: cannot create target: {e}", file=sys.stderr)
        return EXIT_USAGE
    if args.rate_limit:
        target = RateLimitedTarget(target, args.rate_limit)
    cfg = RunConfig(
        target=target,
        scenarios=scenarios,
        payloads=payloads,
        chains=chains,
        repeats=args.repeats,
        seed=str(args.seed),
        concurrency=args.concurrency,
        positions=positions,
        controls=not args.no_controls,
        max_turns=args.max_turns,
        target_label=args.target if not Path(args.target).is_file() else target.name,
    )
    trials, skipped = plan_trials(cfg)
    if args.dry_run:
        print(f"{len(trials)} trials planned ({skipped} incompatible scenario/payload pairs skipped)")
        return EXIT_OK
    if not args.quiet:
        print(
            f"running {len(trials)} trials against {target.name} with concurrency {args.concurrency} ...",
            file=sys.stderr,
        )

    def progress(done: int, total: int) -> None:
        if not args.quiet and (done == total or done % max(1, total // 10) == 0):
            print(f"  {done}/{total}", file=sys.stderr)

    out_dir = Path(args.out)
    res = run(cfg, out_dir=out_dir, progress=progress)
    if not args.no_report:
        write_html_report(out_dir, max_transcripts=args.max_transcripts)
        write_junit(out_dir)
    _print_summary(res)
    print(f"\nresults: {out_dir / 'results.json'}")
    if not args.no_report:
        print(f"report:  {out_dir / 'report.html'}\njunit:   {out_dir / 'junit.xml'}")
    ov = res["summary"]["overall"]
    if args.fail_on_asr is not None and ov["asr"] > args.fail_on_asr:
        print(
            f"FAIL: ASR {ov['asr'] * 100:.1f}% exceeds --fail-on-asr {args.fail_on_asr * 100:.1f}%",
            file=sys.stderr,
        )
        return EXIT_FAIL
    if args.fail_on_error and ov["errors"]:
        print(f"FAIL: {ov['errors']} trial(s) errored", file=sys.stderr)
        return EXIT_FAIL
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    try:
        html_path = write_html_report(args.results, args.html, max_transcripts=args.max_transcripts)
        junit_path = write_junit(args.results, args.junit)
        res = load_results(args.results)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    _print_summary(res)
    print(f"\nreport: {html_path}\njunit:  {junit_path}")
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    try:
        base = load_results(args.baseline)
        cur = load_results(args.current)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    cmp = compare(base, cur, tolerance=args.tolerance, min_trials=args.min_trials)
    if args.json:
        print(json.dumps({**cmp.to_dict(), "failed": cmp.failed(args.strict)}, indent=2))
    else:
        print(format_comparison(cmp, base, cur))
    if cmp.failed(args.strict):
        if not args.json:
            print("\nFAIL: injection resistance regressed", file=sys.stderr)
        return EXIT_FAIL
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    try:
        if args.what == "scenarios":
            for s in load_scenarios(_paths(args.scenarios, "scenarios")):
                tools = ",".join(t.name + ("*" if t.trusted else "") for t in s.tools)
                print(
                    f"{s.id:<22} goals={len(s.goals)} tools=[{tools}] inject={s.injection['document']}"
                    f"#{s.injection_chunk}/{s.injection_position}  {s.name}"
                )
        elif args.what == "payloads":
            for p in load_payloads(_paths(args.payloads, "payloads")):
                extra = f" lang={p.language}" if p.language != "en" else ""
                print(f"{p.id:<34} goal={p.goal:<22} technique={p.technique}{extra}")
        elif args.what == "mutators":
            for spec in REGISTRY.values():
                alias = f" (aliases: {', '.join(spec.aliases)})" if spec.aliases else ""
                params = f" params: {spec.defaults}" if spec.defaults else ""
                print(f"{spec.name:<14} {spec.description}{alias}{params}")
        elif args.what == "targets":
            for k, v in TARGET_KINDS.items():
                print(f"{k:<20} {v}")
    except SuiteError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    paths = args.paths or [bundled_dir("scenarios"), bundled_dir("payloads")]
    try:
        n, errors = validate_paths(paths)
    except SuiteError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    for e in errors:
        print(f"invalid: {e}")
    print(f"{n} file(s) checked, {len(errors)} error(s)")
    return EXIT_FAIL if errors else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="injectlab",
        description="Indirect prompt-injection test harness for tool-using LLM agents. "
        "Only test systems you own or are authorized to test.",
    )
    p.add_argument("--version", action="version", version=f"injectlab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the scenario x payload x mutator matrix against a target")
    r.add_argument(
        "--target",
        required=True,
        help="mock:naive | mock:guarded | openai:<model> | anthropic:<model> | target.yaml",
    )
    r.add_argument(
        "--scenarios", action="append", help="scenario file/dir (repeatable; default: bundled suite)"
    )
    r.add_argument(
        "--payloads", action="append", help="payload file/dir (repeatable; default: bundled library)"
    )
    r.add_argument(
        "--mutators", default="", help="comma-separated variants, '+' composes: b64,zwsp,homoglyph+split:k=4"
    )
    r.add_argument("--no-baseline", action="store_true", help="do not add the unmutated 'none' variant")
    r.add_argument("--repeats", type=int, default=1)
    r.add_argument(
        "--seed", default="0", help="run seed; same seed => same canaries, mutations and trial ids"
    )
    r.add_argument("--concurrency", type=int, default=4)
    r.add_argument(
        "--rate-limit", type=float, default=None, help="max model requests per second (all workers)"
    )
    r.add_argument("--positions", help=f"override injection positions: {','.join(POSITIONS)}")
    r.add_argument("--goals", help=f"only payloads with these goals: {','.join(GOALS)}")
    r.add_argument("--techniques", help="only payloads with these techniques")
    r.add_argument("--only-scenarios", help="comma-separated scenario id globs")
    r.add_argument("--only-payloads", help="comma-separated payload id globs")
    r.add_argument("--max-turns", type=int, default=None, help="override every scenario's max_turns")
    r.add_argument("--no-controls", action="store_true", help="skip benign (no-injection) control trials")
    r.add_argument("--out", default="results", help="output directory")
    r.add_argument("--no-report", action="store_true", help="skip report.html / junit.xml")
    r.add_argument("--max-transcripts", type=int, default=300, help="transcripts embedded in report.html")
    r.add_argument("--fail-on-asr", type=float, default=None, help="exit 1 if overall ASR exceeds this (0-1)")
    r.add_argument("--fail-on-error", action="store_true", help="exit 1 if any trial errored")
    r.add_argument("--dry-run", action="store_true", help="only print the number of planned trials")
    r.add_argument("-q", "--quiet", action="store_true")
    r.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="(re)generate report.html and junit.xml from a results directory")
    rp.add_argument("results", help="results directory or results.json")
    rp.add_argument("--html", help="output path for the HTML report")
    rp.add_argument("--junit", help="output path for JUnit XML")
    rp.add_argument("--max-transcripts", type=int, default=300)
    rp.set_defaults(func=cmd_report)

    c = sub.add_parser("compare", help="compare two runs; exit 1 on regressions beyond tolerance")
    c.add_argument("baseline", help="baseline results dir or results.json")
    c.add_argument("current", help="current results dir or results.json")
    c.add_argument(
        "--tolerance", type=float, default=0.05, help="allowed absolute ASR increase (0-1), default 0.05"
    )
    c.add_argument("--min-trials", type=int, default=1, help="ignore groups with fewer completed trials")
    c.add_argument(
        "--strict", action="store_true", help="also fail if any individual trial became compromised"
    )
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_compare)

    ls = sub.add_parser("list", help="list scenarios, payloads, mutators or targets")
    ls.add_argument("what", choices=["scenarios", "payloads", "mutators", "targets"])
    ls.add_argument("--scenarios", action="append")
    ls.add_argument("--payloads", action="append")
    ls.set_defaults(func=cmd_list)

    v = sub.add_parser("validate", help="schema-validate scenario and payload YAML files")
    v.add_argument("paths", nargs="*", help="files/dirs (default: bundled suite)")
    v.set_defaults(func=cmd_validate)
    return p


def main(argv: list[str] | None = None) -> int:
    # Payloads include non-ASCII text; never crash on a legacy console code page.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
