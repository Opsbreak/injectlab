from __future__ import annotations

import json
import subprocess
import sys

from injectlab.cli import main


def run_cli(*args):
    return main(list(args))


def test_list_commands(capsys):
    assert run_cli("list", "scenarios") == 0
    out = capsys.readouterr().out
    assert "email-assistant" in out and "multi-agent-handoff" in out and "delegate_research*" in out
    assert run_cli("list", "payloads") == 0
    assert "exfil.multilingual_fr" in capsys.readouterr().out
    assert run_cli("list", "mutators") == 0
    out = capsys.readouterr().out
    assert "tag_smuggle" in out and "zwsp" in out
    assert run_cli("list", "targets") == 0
    assert "mock:guarded" in capsys.readouterr().out


def test_validate_ok_and_failure(tmp_path, capsys):
    assert run_cli("validate") == 0
    assert "0 error(s)" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\nsystem_prompt: hi\n", encoding="utf-8")
    assert run_cli("validate", str(bad)) == 1
    assert "missing required property" in capsys.readouterr().out


def test_run_end_to_end_and_report(tmp_path, capsys):
    out = tmp_path / "res"
    code = run_cli(
        "run",
        "--target",
        "mock:naive",
        "--mutators",
        "b64,zwsp",
        "--repeats",
        "2",
        "--only-scenarios",
        "email-*,browser-*",
        "--out",
        str(out),
        "-q",
    )
    assert code == 0
    stdout = capsys.readouterr().out
    assert "ATTACK SUCCESS RATE" in stdout
    for f in ("results.json", "transcripts.jsonl", "report.html", "junit.xml"):
        assert (out / f).is_file()
    res = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert res["config"]["mutators"] == ["none", "base64", "zero_width"]
    assert res["summary"]["overall"]["asr"] > 0.9
    (out / "report.html").unlink()
    assert run_cli("report", str(out)) == 0
    assert (out / "report.html").is_file()


def test_run_fail_on_asr_gate(tmp_path):
    common = [
        "run",
        "--only-scenarios",
        "coding-agent",
        "--goals",
        "unauthorized_tool_call",
        "-q",
        "--no-report",
    ]
    assert (
        run_cli(*common, "--target", "mock:naive", "--out", str(tmp_path / "n"), "--fail-on-asr", "0.1") == 1
    )
    assert (
        run_cli(*common, "--target", "mock:guarded", "--out", str(tmp_path / "g"), "--fail-on-asr", "0.1")
        == 0
    )


def test_compare_cli_exit_codes(tmp_path, capsys):
    common = ["run", "--only-scenarios", "email-assistant,finance-assistant", "-q", "--no-report"]
    run_cli(*common, "--target", "mock:guarded", "--out", str(tmp_path / "base"))
    run_cli(*common, "--target", "mock:naive", "--out", str(tmp_path / "cur"))
    capsys.readouterr()
    assert run_cli("compare", str(tmp_path / "base"), str(tmp_path / "cur")) == 1
    assert "REGRESSIONS" in capsys.readouterr().out
    assert run_cli("compare", str(tmp_path / "base"), str(tmp_path / "base" / "results.json")) == 0
    capsys.readouterr()
    assert run_cli("compare", str(tmp_path / "cur"), str(tmp_path / "base"), "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["failed"] is False and data["improvements"]
    assert run_cli("compare", str(tmp_path / "nope"), str(tmp_path / "base")) == 2


def test_usage_errors(tmp_path, capsys):
    assert run_cli("run", "--target", "mock:naive", "--mutators", "notamutator", "--out", str(tmp_path)) == 2
    assert run_cli("run", "--target", "nope:x", "--out", str(tmp_path)) == 2
    assert run_cli("run", "--target", "mock:naive", "--goals", "pwn", "--out", str(tmp_path)) == 2
    assert run_cli("run", "--target", "mock:naive", "--dry-run", "--repeats", "3") == 0
    assert "trials planned" in capsys.readouterr().out


def test_console_script_module_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "injectlab", "--version"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0 and "injectlab 0.1.0" in proc.stdout
