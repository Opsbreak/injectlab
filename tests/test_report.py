from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

from injectlab.mutators import parse_chains
from injectlab.report import load_results
from injectlab.report.compare import compare, format_comparison
from injectlab.report.html import write_html_report
from injectlab.report.junit import build_junit, write_junit
from injectlab.runner import RunConfig, run
from injectlab.suite import load_payloads
from injectlab.summary import wilson
from injectlab.targets.mock import GuardedMockModel, NaiveMockModel


@pytest.fixture(scope="module")
def runs(tmp_path_factory, scenarios, payloads):
    ss = [scenarios["email-assistant"], scenarios["markdown-chat"], scenarios["multi-agent-handoff"]]
    ps = [
        payloads[p]
        for p in (
            "exfil.direct_override",
            "exfil.html_comment",
            "hijack.direct_override",
            "action.direct_override",
        )
    ]
    out = {}
    for name, model in (("naive", NaiveMockModel()), ("guarded", GuardedMockModel())):
        d = tmp_path_factory.mktemp(name)
        run(RunConfig(target=model, scenarios=ss, payloads=ps, chains=parse_chains("tags")), out_dir=d)
        out[name] = d
    return out


def test_html_report_is_self_contained(runs):
    path = write_html_report(runs["naive"])
    html = path.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert not re.search(r"<script[^>]+src=", html, re.I)
    assert not re.search(r"<link\b", html, re.I)
    assert "@import" not in html
    assert "Attack success rate" in html and "Scenario x technique" in html
    data = re.search(r'<script id="ilab-data" type="application/json">(.*?)</script>', html, re.S).group(1)
    parsed = json.loads(data)
    assert parsed["cases"] and set(parsed["transcripts"]) <= {c["trial_id"] for c in parsed["cases"]}
    assert "prefers-color-scheme:dark" in html


def test_html_report_escapes_attacker_content(tmp_path, scenarios):
    pfile = tmp_path / "evil.yaml"
    pfile.write_text(
        yaml.safe_dump(
            {
                "payloads": [
                    {
                        "id": "evil.script",
                        "goal": "goal_hijack",
                        "technique": "xss_probe",
                        "template": "</script><script>alert(1)</script><img src=x onerror=alert(2)> {{instruction}}",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ps = load_payloads([pfile])
    out = tmp_path / "res"
    run(
        RunConfig(
            target=NaiveMockModel(),
            scenarios=[scenarios["email-assistant"]],
            payloads=ps,
            chains=parse_chains(""),
        ),
        out_dir=out,
    )
    html = write_html_report(out).read_text(encoding="utf-8")
    assert "<script>alert(1)" not in html
    assert "onerror=alert(2)>" not in html
    assert html.count("<script") == 2  # only the data block and the viewer code


def test_junit_xml(runs):
    path = write_junit(runs["naive"])
    root = ET.parse(path).getroot()
    res = load_results(runs["naive"])
    assert root.tag == "testsuites"
    assert int(root.get("tests")) == len(res["trials"])
    assert int(root.get("failures")) == res["summary"]["overall"]["successes"]
    names = {s.get("name") for s in root.findall("testsuite")}
    assert names == {"injectlab.email-assistant", "injectlab.markdown-chat", "injectlab.multi-agent-handoff"}
    assert root.find(".//failure").get("type") == "InjectionSucceeded"


def test_junit_strips_invalid_xml_chars():
    res = {
        "trials": [
            {
                "scenario": "s",
                "payload": "p\x01",
                "mutators": "none",
                "position": "suffix",
                "repeat": 0,
                "goal": "g",
                "status": "error",
                "error": "bad \x00 byte",
                "trial_id": "t",
                "oracles": [],
                "violations": [],
                "success": False,
            }
        ]
    }
    ET.fromstring(build_junit(res).split("\n", 1)[1])


def test_compare_flags_regression_and_passes_on_identical(runs):
    base, cur = load_results(runs["guarded"]), load_results(runs["naive"])
    regress = compare(base, cur, tolerance=0.05)
    assert regress.failed()
    assert any(d.dimension == "overall" for d in regress.regressions)
    assert regress.new_compromises
    assert "REGRESSIONS" in format_comparison(regress, base, cur)
    same = compare(cur, cur)
    assert not same.failed(strict=True) and not same.new_compromises
    improved = compare(cur, base)
    assert not improved.failed() and improved.improvements and improved.fixed


def test_compare_tolerance_and_strict(runs):
    base, cur = load_results(runs["guarded"]), load_results(runs["naive"])
    lenient = compare(base, cur, tolerance=1.0)
    assert not lenient.failed()
    assert lenient.failed(strict=True)  # individual trials still flipped to compromised


def test_wilson_interval():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and 0.25 < hi < 0.35
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and 0.65 < lo < 0.75
    assert wilson(0, 0) == (0.0, 0.0)
