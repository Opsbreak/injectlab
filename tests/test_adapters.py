"""OpenAI / Anthropic / webhook adapters against a local fake server speaking each wire format."""

from __future__ import annotations

import json

import pytest

from injectlab.agent import run_agent
from injectlab.conversation import Message, ToolCall, ToolSpec
from injectlab.sandbox import ToolSandbox
from injectlab.suite import ToolDef
from injectlab.targets import make_target
from injectlab.targets.anthropic import AnthropicTarget
from injectlab.targets.base import RateLimitedTarget, TargetError
from injectlab.targets.http import HTTPStatusError, RetryPolicy, expand_env
from injectlab.targets.openai import OpenAITarget
from injectlab.targets.webhook import WebhookTarget, jsonpath_get

TOOLS = [
    ToolDef(
        "get_weather",
        "Weather for a city",
        {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]},
        {"type": "template", "template": "Sunny in {{args.city}}"},
    ),
]


def sandbox():
    return ToolSandbox(TOOLS, {}, {})


# ---- OpenAI wire format --------------------------------------------------------------------
def oa_tool_call(name, args, cid="call_1"):
    return (
        200,
        {},
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": cid,
                                "type": "function",
                                "function": {"name": name, "arguments": json.dumps(args)},
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
    )


def oa_text(text):
    return (
        200,
        {},
        {
            "id": "chatcmpl-2",
            "choices": [
                {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}
            ],
        },
    )


def openai_target(server, retry=None, **kw):
    return OpenAITarget(
        "gpt-test",
        base_url=server.url + "/v1",
        api_key="sk-test",
        retry=retry or RetryPolicy(max_retries=0),
        **kw,
    )


def test_openai_tool_calling_loop(fake_server):
    fake_server.push(oa_tool_call("get_weather", {"city": "Toronto"}), oa_text("It is sunny in Toronto."))
    t = run_agent(
        openai_target(fake_server), sandbox(), system_prompt="sys", user_message="Weather in Toronto?"
    )
    assert t.final_output == "It is sunny in Toronto." and t.turns == 2
    assert t.executions[0].arguments == {"city": "Toronto"}
    first, second = (r["body"] for r in fake_server.requests)
    assert fake_server.requests[0]["path"] == "/v1/chat/completions"
    assert fake_server.requests[0]["headers"]["authorization"] == "Bearer sk-test"
    assert first["model"] == "gpt-test" and first["tool_choice"] == "auto"
    assert first["tools"][0] == {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Weather for a city",
            "parameters": TOOLS[0].parameters,
        },
    }
    assert [m["role"] for m in first["messages"]] == ["system", "user"]
    assistant, tool = second["messages"][2], second["messages"][3]
    assert assistant["tool_calls"][0]["function"] == {
        "name": "get_weather",
        "arguments": '{"city": "Toronto"}',
    }
    assert tool == {"role": "tool", "tool_call_id": "call_1", "content": "Sunny in Toronto"}


def test_openai_retries_on_429_and_5xx(fake_server, fast_retry):
    fake_server.push(
        (429, {"Retry-After": "0"}, {"error": "rate limited"}), (503, {}, {"error": "busy"}), oa_text("ok")
    )
    r = openai_target(fake_server, fast_retry).complete([Message("user", "hi")], [])
    assert r.content == "ok"
    assert len(fake_server.requests) == 3
    assert fast_retry.sleeps[0] == 0.0  # honoured Retry-After
    assert 0 < fast_retry.sleeps[1] <= 0.05


def test_openai_gives_up_after_max_retries(fake_server, fast_retry):
    fake_server.default = (500, {}, {"error": "down"})
    with pytest.raises(TargetError, match="giving up after 4 attempts"):
        openai_target(fake_server, fast_retry).complete([Message("user", "hi")], [])
    assert len(fake_server.requests) == 4


def test_openai_does_not_retry_400(fake_server, fast_retry):
    fake_server.push((400, {}, {"error": {"message": "bad request"}}))
    with pytest.raises(HTTPStatusError) as ei:
        openai_target(fake_server, fast_retry).complete([Message("user", "hi")], [])
    assert ei.value.status == 400 and len(fake_server.requests) == 1


def test_openai_timeout_is_retried_then_fails(fake_server):
    fake_server.delay = 0.6
    fake_server.default = oa_text("late")
    target = openai_target(
        fake_server, RetryPolicy(max_retries=1, backoff_base=0.01, sleep=lambda s: None), timeout=0.2
    )
    with pytest.raises(TargetError, match="giving up after 2 attempts"):
        target.complete([Message("user", "hi")], [])


def test_openai_malformed_arguments_and_params(fake_server):
    fake_server.push(
        (
            200,
            {},
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c",
                                    "type": "function",
                                    "function": {"name": "get_weather", "arguments": "{not json"},
                                }
                            ],
                        }
                    }
                ]
            },
        )
    )
    r = openai_target(fake_server, params={"temperature": 0}).complete([Message("user", "hi")], [])
    assert r.tool_calls[0].arguments == {"_raw_arguments": "{not json"}
    assert fake_server.requests[0]["body"]["temperature"] == 0


def test_openai_requires_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(TargetError, match="OPENAI_API_KEY"):
        OpenAITarget("m")


# ---- Anthropic wire format -----------------------------------------------------------------
def an_tool_use(name, args, tid="toolu_01"):
    return (
        200,
        {},
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "sig-abc"},
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": tid, "name": name, "input": args},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 9},
        },
    )


def an_text(text):
    return (
        200,
        {},
        {
            "id": "msg_2",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
        },
    )


def anthropic_target(server, retry=None):
    return AnthropicTarget(
        "claude-test", base_url=server.url, api_key="ak-test", retry=retry or RetryPolicy(max_retries=0)
    )


def test_anthropic_tool_use_loop(fake_server):
    fake_server.push(an_tool_use("get_weather", {"city": "Oslo"}), an_text("Sunny in Oslo."))
    t = run_agent(
        anthropic_target(fake_server), sandbox(), system_prompt="be brief", user_message="Weather in Oslo?"
    )
    assert t.final_output == "Sunny in Oslo." and t.executions[0].arguments == {"city": "Oslo"}
    req1, req2 = fake_server.requests
    assert req1["path"] == "/v1/messages"
    assert req1["headers"]["x-api-key"] == "ak-test" and req1["headers"]["anthropic-version"] == "2023-06-01"
    b1 = req1["body"]
    assert b1["system"] == "be brief" and b1["max_tokens"] == 4096
    assert b1["tools"] == [
        {"name": "get_weather", "description": "Weather for a city", "input_schema": TOOLS[0].parameters}
    ]
    assert b1["messages"] == [{"role": "user", "content": [{"type": "text", "text": "Weather in Oslo?"}]}]
    msgs = req2["body"]["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    # assistant turn replayed verbatim, including the thinking block and its signature
    assert msgs[1]["content"][0] == {"type": "thinking", "thinking": "", "signature": "sig-abc"}
    assert msgs[1]["content"][2]["type"] == "tool_use"
    assert msgs[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "toolu_01", "content": "Sunny in Oslo"}
    ]


def test_anthropic_parallel_tool_results_merge_into_one_user_message():
    msgs = [
        Message("system", "s"),
        Message("user", "u"),
        Message("assistant", "", tool_calls=[ToolCall("a", "x", {}), ToolCall("b", "x", {})]),
        Message("tool", "r1", tool_call_id="a"),
        Message("tool", "r2", tool_call_id="b"),
    ]
    system, wire = AnthropicTarget.to_wire(msgs)
    assert system == "s"
    assert wire[-1]["role"] == "user" and [b["tool_use_id"] for b in wire[-1]["content"]] == ["a", "b"]


def test_anthropic_retries_on_429_and_529(fake_server, fast_retry):
    fake_server.push(
        (429, {"retry-after": "0"}, {"type": "error", "error": {"type": "rate_limit_error"}}),
        (529, {}, {"type": "error", "error": {"type": "overloaded_error"}}),
        an_text("ok"),
    )
    assert anthropic_target(fake_server, fast_retry).complete([Message("user", "hi")], []).content == "ok"
    assert len(fake_server.requests) == 3


def test_anthropic_refusal_stop_reason(fake_server):
    fake_server.push((200, {}, {"type": "message", "content": [], "stop_reason": "refusal"}))
    r = anthropic_target(fake_server).complete([Message("user", "hi")], [])
    assert r.stop_reason == "refusal" and r.content == "" and r.tool_calls == []


# ---- generic webhook -----------------------------------------------------------------------
def test_jsonpath_subset():
    doc = {"a": {"b": [{"c": 1}, {"c": 2}]}, "x-y": {"k": "v"}}
    assert jsonpath_get(doc, "$.a.b[1].c") == 2
    assert jsonpath_get(doc, "$['x-y'].k") == "v"
    assert jsonpath_get(doc, "a.b[5].c", "dflt") == "dflt"
    assert jsonpath_get(doc, "$") is doc


def test_webhook_target_with_mapping_and_body_template(fake_server, monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN", "tok-123")
    fake_server.push(
        (
            200,
            {},
            {
                "output": {
                    "text": "",
                    "actions": [{"tool": "get_weather", "params": '{"city": "Lima"}', "ref": "r1"}],
                }
            },
        ),
        (200, {}, {"output": {"text": "Sunny in Lima.", "actions": []}}),
    )
    target = WebhookTarget(
        fake_server.url + "/agent",
        headers={"Authorization": "Bearer ${AGENT_TOKEN}"},
        body={"conversation": "$messages", "functions": "$tools", "q": "$last_user"},
        response={
            "content": "$.output.text",
            "tool_calls": "$.output.actions",
            "tool_name": "$.tool",
            "tool_arguments": "$.params",
            "tool_id": "$.ref",
        },
        retry=RetryPolicy(max_retries=0),
    )
    t = run_agent(target, sandbox(), system_prompt="s", user_message="Lima weather?")
    assert t.final_output == "Sunny in Lima." and t.executions[0].arguments == {"city": "Lima"}
    req = fake_server.requests[0]
    assert req["headers"]["authorization"] == "Bearer tok-123"
    assert req["body"]["q"] == "Lima weather?" and req["body"]["functions"][0]["name"] == "get_weather"
    assert fake_server.requests[1]["body"]["conversation"][-1] == {
        "role": "tool",
        "content": "Sunny in Lima",
        "tool_call_id": "r1",
        "name": "get_weather",
    }


def test_expand_env_missing_variable_raises(monkeypatch):
    monkeypatch.delenv("NOPE_NOT_SET", raising=False)
    with pytest.raises(TargetError):
        expand_env("Bearer ${NOPE_NOT_SET}")


def test_make_target_specs_and_config_file(tmp_path, monkeypatch):
    assert make_target("mock:naive").name == "mock:naive"
    monkeypatch.setenv("MY_KEY", "k")
    cfg = tmp_path / "t.yaml"
    cfg.write_text(
        "type: openai\nmodel: local-model\nbase_url: http://127.0.0.1:9/v1\napi_key_env: MY_KEY\n",
        encoding="utf-8",
    )
    t = make_target(str(cfg))
    assert isinstance(t, OpenAITarget) and t.model == "local-model" and t.base_url == "http://127.0.0.1:9/v1"
    with pytest.raises(TargetError):
        make_target("bogus:thing")


def test_rate_limited_target_spaces_calls():
    import time

    from injectlab.targets.mock import NaiveMockModel

    t = RateLimitedTarget(NaiveMockModel(), rate=20)
    start = time.monotonic()
    for _ in range(5):
        t.complete([Message("system", "s"), Message("user", "u")], [ToolSpec("x", "y", {})])
    assert time.monotonic() - start >= 0.18


def test_example_target_configs_load(monkeypatch):
    from .conftest import ROOT

    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "y")
    kinds = {
        p.name: type(make_target(str(p))).__name__ for p in sorted((ROOT / "examples").glob("target-*.yaml"))
    }
    assert kinds == {
        "target-anthropic.yaml": "AnthropicTarget",
        "target-openai.yaml": "OpenAITarget",
        "target-webhook.yaml": "WebhookTarget",
    }
