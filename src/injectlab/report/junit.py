"""JUnit XML: one testsuite per scenario, one testcase per attack trial.

A successful attack is a ``<failure>`` (the defence failed); a trial that could not run is an
``<error>``. Control trials appear as ``control`` test cases that fail when an oracle fires
without any attack present.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

from injectlab.report import load_results

# Characters not allowed in XML 1.0.
_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")


def _clean(s: Any) -> str:
    return _INVALID_XML.sub("�", str(s))


def build_junit(results: dict[str, Any]) -> str:
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for t in results["trials"]:
        by_scenario[t["scenario"]].append(t)
    root = ET.Element("testsuites", name="injectlab", tests="0", failures="0", errors="0")
    totals = {"tests": 0, "failures": 0, "errors": 0}
    for scen in sorted(by_scenario):
        trials = by_scenario[scen]
        suite = ET.SubElement(root, "testsuite", name=_clean(f"injectlab.{scen}"))
        counts = {"tests": 0, "failures": 0, "errors": 0}
        time_total = 0.0
        for t in trials:
            counts["tests"] += 1
            secs = float(t.get("duration_ms", 0)) / 1000
            time_total += secs
            name = f"{t['payload']} [{t['mutators']}|{t['position']}|r{t['repeat']}]"
            case = ET.SubElement(
                suite,
                "testcase",
                classname=_clean(f"injectlab.{scen}.{t['goal']}"),
                name=_clean(name),
                time=f"{secs:.3f}",
            )
            if t["status"] == "error":
                counts["errors"] += 1
                err = ET.SubElement(case, "error", message="trial error", type="TrialError")
                err.text = _clean(t.get("error") or "")
            elif t.get("control") and t["violations"]:
                counts["failures"] += 1
                f = ET.SubElement(
                    case,
                    "failure",
                    message=_clean("oracle fired on benign control: " + ", ".join(t["violations"])),
                    type="FalseAlarm",
                )
                f.text = _clean(
                    json.dumps([o for o in t["oracles"] if o["fired"]], ensure_ascii=False, indent=1)
                )
            elif t.get("success"):
                counts["failures"] += 1
                fired = [o for o in t["oracles"] if o["fired"]]
                f = ET.SubElement(
                    case,
                    "failure",
                    message=_clean("attack succeeded: " + ", ".join(o["id"] for o in fired)),
                    type="InjectionSucceeded",
                )
                f.text = _clean(
                    json.dumps({"trial_id": t["trial_id"], "evidence": fired}, ensure_ascii=False, indent=1)
                )
        for k, v in counts.items():
            suite.set(k, str(v))
            totals[k] += v
        suite.set("time", f"{time_total:.3f}")
    for k, v in totals.items():
        root.set(k, str(v))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def write_junit(results_path: str | Path, out_path: str | Path | None = None) -> Path:
    results = load_results(results_path)
    rp = Path(results_path)
    out = Path(out_path) if out_path else (rp if rp.is_dir() else rp.parent) / "junit.xml"
    out.write_text(build_junit(results), encoding="utf-8")
    return out
