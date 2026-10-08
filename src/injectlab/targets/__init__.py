"""Target factory.

Accepted ``--target`` forms:

* ``mock:naive`` / ``mock:guarded`` - built-in deterministic models
* ``openai:<model>`` - OpenAI-compatible endpoint (``OPENAI_BASE_URL``, ``OPENAI_API_KEY``)
* ``anthropic:<model>`` - Anthropic Messages API (``ANTHROPIC_API_KEY``)
* a path to a ``.yaml`` / ``.json`` target config file (see README)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from injectlab.targets.anthropic import AnthropicTarget
from injectlab.targets.base import RateLimitedTarget, Target, TargetError
from injectlab.targets.http import RetryPolicy
from injectlab.targets.mock import GuardedMockModel, NaiveMockModel
from injectlab.targets.openai import OpenAITarget
from injectlab.targets.webhook import WebhookTarget

__all__ = [
    "AnthropicTarget",
    "GuardedMockModel",
    "NaiveMockModel",
    "OpenAITarget",
    "RateLimitedTarget",
    "Target",
    "TargetError",
    "WebhookTarget",
    "make_target",
]

MOCKS: dict[str, type[Target]] = {"mock:naive": NaiveMockModel, "mock:guarded": GuardedMockModel}

TARGET_KINDS = {
    "mock:naive": "Deterministic over-compliant agent (vulnerable by design).",
    "mock:guarded": "Deterministic agent with data/instruction separation; trusts tools marked trusted.",
    "openai:<model>": "Any OpenAI-compatible /chat/completions endpoint with tool calling.",
    "anthropic:<model>": "Anthropic Messages API with tool_use blocks.",
    "<file>.yaml": "Target config file (type: openai | anthropic | http | mock).",
}


def _retry_from(cfg: dict[str, Any]) -> RetryPolicy:
    return RetryPolicy(
        max_retries=int(cfg.get("max_retries", 4)),
        backoff_base=float(cfg.get("backoff_base", 1.0)),
        backoff_max=float(cfg.get("backoff_max", 30.0)),
    )


def target_from_config(cfg: dict[str, Any]) -> Target:
    kind = str(cfg.get("type", "")).lower()
    timeout = float(cfg.get("timeout", 60.0))
    if kind == "mock":
        spec = f"mock:{cfg.get('model', 'naive')}"
        if spec not in MOCKS:
            raise TargetError(f"unknown mock model: {spec}")
        return MOCKS[spec]()
    if kind == "openai":
        return OpenAITarget(
            cfg["model"],
            base_url=cfg.get("base_url"),
            api_key_env=cfg.get("api_key_env", "OPENAI_API_KEY"),
            headers=cfg.get("headers"),
            params=cfg.get("params"),
            timeout=timeout,
            retry=_retry_from(cfg),
            require_key=bool(cfg.get("require_api_key", True)),
        )
    if kind == "anthropic":
        return AnthropicTarget(
            cfg["model"],
            base_url=cfg.get("base_url"),
            api_key_env=cfg.get("api_key_env", "ANTHROPIC_API_KEY"),
            max_tokens=int(cfg.get("max_tokens", 4096)),
            headers=cfg.get("headers"),
            params=cfg.get("params"),
            timeout=float(cfg.get("timeout", 120.0)),
            retry=_retry_from(cfg),
            require_key=bool(cfg.get("require_api_key", True)),
        )
    if kind == "http":
        return WebhookTarget(
            cfg["url"],
            headers=cfg.get("headers"),
            body=cfg.get("body"),
            response=cfg.get("response"),
            timeout=timeout,
            retry=_retry_from(cfg),
            name=cfg.get("name"),
        )
    raise TargetError(f"unknown target type '{kind}' (expected openai, anthropic, http or mock)")


def make_target(spec: str | dict[str, Any]) -> Target:
    if isinstance(spec, dict):
        return target_from_config(spec)
    if spec in MOCKS:
        return MOCKS[spec]()
    p = Path(spec)
    if p.suffix.lower() in (".yaml", ".yml", ".json") and p.is_file():
        text = p.read_text(encoding="utf-8")
        cfg = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
        if not isinstance(cfg, dict):
            raise TargetError(f"{p}: target config must be a mapping")
        return target_from_config(cfg)
    kind, sep, model = spec.partition(":")
    if sep and model and kind == "openai":
        return OpenAITarget(model)
    if sep and model and kind == "anthropic":
        return AnthropicTarget(model)
    raise TargetError(f"unknown target '{spec}'. Known: {', '.join(TARGET_KINDS)}")
