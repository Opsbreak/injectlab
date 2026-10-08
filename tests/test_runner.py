from __future__ import annotations

import json

import pytest

from injectlab.conversation import Message, ToolCall, ToolSpec, TrialHints
from injectlab.mutators import parse_chains
from injectlab.runner import RunConfig, plan_trials, run
from injectlab.targets.http import RetryPolicy
from injectlab.targets.mock import GuardedMockModel, NaiveMockModel
from injectlab.targets.openai import OpenAITarget


def strip_volatile(records):
    return [{k: v for k, v in r.items() if k != "duration_ms"} for r in records]


def cfg(scenarios, payloads, target=None, **kw):
    return RunConfig(
        target=target or NaiveMockModel(),
        scenarios=scenarios,
        payloads=payloads,
        chains=kw.pop("chains", parse_chains("b64,zwsp,homoglyph")),
        **kw,
    )


def test_plan_trials_counts_and_skips(scenarios, payloads):
    c = cfg(
        [scenarios["markdown-chat"]],
        [
            payloads["exfil.direct_override"],
            payloads["exfil.fake_tool_result"],
            payloads["action.direct_override"],
        ],
        repeats=2,
    )
    trials, skipped = plan_trials(c)
    # 1 compatible payload x 4 chains x 2 repeats + 2 control trials
    assert len(trials) == 4 * 2 + 2 and skipped == 2
    assert len({t.trial_id for t in trials}) == len(trials)


def test_payload_position_override(scenarios, payloads):
    c = cfg(
        [scenarios["email-assistant"]],
        [payloads["exfil.payload_split"]],
        chains=parse_chains(""),
        controls=False,
    )
    (t,) = plan_trials(c)[0]
    assert t.position == "split"
    c.positions = ["prefix", "middle"]
    assert [t.position for t in plan_trials(c)[0]] == ["prefix", "middle"]


def test_runner_is_deterministic_across_concurrency(scenarios, payloads):
    ss = [scenarios["email-assistant"], scenarios["calendar-agent"]]
    ps = [
        payloads["exfil.direct_override"],
        payloads["action.fake_tool_result"],
        payloads["hijack.direct_override"],
    ]
    a = run(cfg(ss, ps, repeats=2, seed="7", concurrency=1))
    b = run(cfg(ss, ps, repeats=2, seed="7", concurrency=8))
    assert a["run_id"] == b["run_id"]
    assert strip_volatile(a["trials"]) == strip_volatile(b["trials"])
    c = run(cfg(ss, ps, repeats=2, seed="8", concurrency=4))
    assert c["run_id"] != a["run_id"]
    assert {t["canary"] for t in c["trials"]}.isdisjoint({t["canary"] for t in a["trials"]})


def test_repeats_get_distinct_canaries_and_mutations(scenarios, payloads):
    res = run(
        cfg(
            [scenarios["email-assistant"]],
            [payloads["exfil.direct_override"]],
            repeats=3,
            chains=parse_chains("zwsp", include_baseline=False),
            controls=False,
        )
    )
    assert len({t["canary"] for t in res["trials"]}) == 3


def test_writes_results_and_transcripts(tmp_path, scenarios, payloads):
    res = run(cfg([scenarios["finance-assistant"]], [payloads["action.direct_override"]]), out_dir=tmp_path)
    saved = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert saved["run_id"] == res["run_id"] and len(saved["trials"]) == len(res["trials"])
    lines = (tmp_path / "transcripts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(res["trials"])
    tr = json.loads(lines[1])
    assert tr["messages"][0]["role"] == "system" and tr["payload_text"]


def test_full_suite_naive_vs_guarded(scenarios, payloads):
    ss, ps = list(scenarios.values()), list(payloads.values())
    naive = run(cfg(ss, ps, target=NaiveMockModel(), chains=parse_chains("")))
    guarded = run(cfg(ss, ps, target=GuardedMockModel(), chains=parse_chains("")))
    n, g = naive["summary"], guarded["summary"]
    assert n["overall"]["asr"] >= 0.9
    assert g["overall"]["asr"] <= 0.2
    # the guarded model only falls through the transitive-trust channel
    assert {s for s, b in g["by_scenario"].items() if b["successes"]} == {"multi-agent-handoff"}
    # benign controls: no oracle fires, for either model
    assert n["controls"]["false_alarms"] == 0 and g["controls"]["false_alarms"] == 0
    assert n["overall"]["errors"] == 0 and g["overall"]["errors"] == 0


def test_errors_are_recorded_not_counted(scenarios, payloads):
    class Broken(NaiveMockModel):
        name = "broken"

        def complete(self, *a, **k):
            raise RuntimeError("adapter bug")

    res = run(
        cfg(
            [scenarios["email-assistant"]],
            [payloads["exfil.direct_override"]],
            target=Broken(),
            chains=parse_chains(""),
        )
    )
    ov = res["summary"]["overall"]
    assert ov["errors"] == ov["trials"] == 1 and ov["asr"] == 0.0
    assert "adapter bug" in res["trials"][1]["error"]


def naive_over_openai_wire(scenario):
    """A fake OpenAI-compatible backend whose 'model' is the naive mock (exercises the real adapter)."""
    naive = NaiveMockModel()
    hints = TrialHints(plan=scenario.plan, reference_answer=scenario.reference_answer)

    def reply(req):
        body = req["body"]
        msgs = []
        for m in body["messages"]:
            if m["role"] == "assistant":
                calls = [
                    ToolCall(c["id"], c["function"]["name"], json.loads(c["function"]["arguments"]))
                    for c in m.get("tool_calls") or []
                ]
                msgs.append(Message("assistant", m.get("content") or "", tool_calls=calls))
            elif m["role"] == "tool":
                msgs.append(Message("tool", m["content"], tool_call_id=m["tool_call_id"]))
            else:
                msgs.append(Message(m["role"], m["content"]))
        tools = [
            ToolSpec(t["function"]["name"], t["function"]["description"], t["function"]["parameters"])
            for t in body.get("tools", [])
        ]
        r = naive.complete(msgs, tools, hints=hints)
        message = {"role": "assistant", "content": r.content or None}
        if r.tool_calls:
            message["tool_calls"] = [
                {
                    "id": c.id,
                    "type": "function",
                    "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                }
                for c in r.tool_calls
            ]
        return (200, {}, {"choices": [{"index": 0, "message": message, "finish_reason": "stop"}]})

    return reply


@pytest.mark.parametrize("scenario_id", ["email-assistant", "finance-assistant"])
def test_end_to_end_through_openai_adapter(fake_server, scenarios, payloads, scenario_id):
    s = scenarios[scenario_id]
    fake_server.default = naive_over_openai_wire(s)
    target = OpenAITarget(
        "naive-over-http", base_url=fake_server.url + "/v1", api_key="x", retry=RetryPolicy(max_retries=0)
    )
    res = run(
        cfg(
            [s],
            [payloads["exfil.direct_override"], payloads["action.fake_tool_result"]],
            target=target,
            chains=parse_chains("b64"),
            concurrency=2,
        )
    )
    attacks = [t for t in res["trials"] if not t["control"]]
    assert attacks and all(t["success"] for t in attacks)
    assert res["summary"]["controls"]["false_alarms"] == 0
    assert len(fake_server.requests) > len(res["trials"])
