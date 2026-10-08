# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-08

First public release.

### Added

- Scenario format (YAML) for tool-using agents: system prompt with a per-trial `{{canary}}`, tools
  with JSON schemas and sandboxed mock behaviours (`static`, `template`, `document`, `router`,
  `error`), untrusted documents delivered through tool results or retrieved context, injection
  points (`prefix`, `suffix`, `middle`, `replace`, `split`), oracles and benign task plans.
- Eight bundled scenarios: email assistant, RAG support bot, coding agent with a shell, browser
  agent, calendar agent, finance assistant, markdown-rendering chat, multi-agent handoff.
- Payload library of 38 templates across five goals (canary exfiltration, unauthorized tool call,
  goal hijack, system-prompt leak, denial) and eleven techniques, including static French,
  Spanish and German phrasings.
- Seeded, composable mutators: base64, ROT13, zero-width insertion, homoglyphs, Unicode tag
  smuggling, HTML comment, hidden HTML element, whitespace padding, chunk splitting.
- Oracles: encoding-aware canary leak detection (case, separators, zero-width, homoglyphs,
  base64 at any alignment, hex, URL encoding, ROT13, reversal, nested encodings, splits across
  outputs), forbidden tool calls with argument predicates, output regex / contains,
  markdown and HTML image/link exfiltration, system-prompt leak, task completion / refusal.
- Targets: OpenAI-compatible chat completions, Anthropic Messages API, generic JSON webhook with
  JSONPath-style response mapping, and two deterministic mock models (`mock:naive`,
  `mock:guarded`). HTTP targets retry 408/409/425/429/5xx/529 and network errors with
  exponential backoff and `Retry-After` support.
- Runner with a worker pool, global rate limiting, deterministic trial ids, canaries and
  mutations per seed, benign control trials, and full JSONL transcripts.
- Reports: JSON results with Wilson confidence intervals, a single-file offline HTML report
  with a transcript viewer, JUnit XML, and `injectlab compare` for CI regression gating.
- CLI: `run`, `report`, `compare`, `list`, `validate`.
