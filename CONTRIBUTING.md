# Contributing to injectlab

Thanks for helping make LLM agents harder to hijack. Contributions of code, scenarios, payloads,
mutators and oracles are all welcome.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Before opening a pull request:

```bash
ruff check src tests
ruff format src tests
injectlab validate
pytest
```

CI runs the same checks on Python 3.10 to 3.13 plus a smoke run against the mock targets.

## Adding a scenario

1. Copy a file from `scenarios/` and give it a unique `id`.
2. Put `{{canary}}` in the system prompt if the scenario supports the `exfiltrate_canary` or
   `system_prompt_leak` goals.
3. Declare every tool with a JSON schema and a mock behaviour (`static`, `template`, `document`,
   `router` or `error`). Mock tools must never cause real side effects.
4. Add oracles for each goal you list in `goals`, and a `task.plan` / `reference_answer` so the
   built-in mock models (and the benign control trial) can complete the task.
5. Run `injectlab validate` and `injectlab run --target mock:naive --only-scenarios <id>`. The
   control trial must report `0 false alarm(s)`: oracles must not fire on a benign run.

## Adding a payload

Payloads are templates. Prefer `{{instruction}}`, which injectlab renders per scenario and goal, so
one payload works across every compatible scenario. Use `{{tool_name}}` / `{{tool_args}}` only
when the technique needs the raw call (for example fake tool-result JSON). Give each payload a
`technique` so results can be grouped.

Payloads in this repository are for defensive testing. Do not contribute payloads that target a
specific real product, person or organisation, or that carry real malware or working credentials.

## Adding a mutator or oracle

- Mutators live in `src/injectlab/mutators.py`. They must be deterministic for a given seed and
  come with round-trip or property tests in `tests/test_mutators.py`.
- Oracles live in `src/injectlab/oracles.py`, with a schema entry in `schema.py`. Add tests for
  both a true positive and a near-miss that must not fire.

## Commit and PR guidelines

- Keep pull requests focused and describe the behaviour change.
- Add or update tests with every change.
- Update `CHANGELOG.md` under an "Unreleased" heading.

## Code of conduct

Be respectful and constructive. Harassment of any kind is not tolerated.
