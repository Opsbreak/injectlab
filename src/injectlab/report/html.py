"""Single-file, self-contained HTML report (no external assets, works offline).

Everything attacker-controlled (payloads, model output, tool arguments) is either escaped with
``html.escape`` on the server side or inserted with ``textContent`` on the client side; the
embedded JSON is escaped so it cannot terminate its ``<script>`` element.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from injectlab.report import load_results, load_transcripts

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# Sequential blue ramp (light -> dark) used for the heatmap.
RAMP = [
    "#cde2fb",
    "#b7d3f6",
    "#9ec5f4",
    "#86b6ef",
    "#6da7ec",
    "#5598e7",
    "#3987e5",
    "#2a78d6",
    "#256abf",
    "#1c5cab",
    "#184f95",
    "#104281",
    "#0d366b",
]


def _e(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _safe_json(obj: Any) -> str:
    s = json.dumps(obj, ensure_ascii=False)
    return (
        s.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def worst_cases(trials: list[dict[str, Any]], limit: int = 200) -> list[dict[str, Any]]:
    def score(t: dict[str, Any]) -> tuple[int, int, str]:
        fired = [o for o in t.get("oracles", []) if o["fired"]]
        sev = max((SEVERITY_RANK.get(o.get("severity", "high"), 3) for o in fired), default=0)
        return (sev, len(fired), t["trial_id"])

    succ = [t for t in trials if t.get("success")]
    return sorted(succ, key=score, reverse=True)[:limit]


def _bars(title: str, buckets: dict[str, Any], note: str = "") -> str:
    rows = sorted(buckets.items(), key=lambda kv: (-kv[1]["asr"], kv[0]))
    out = [f'<section class="card"><h3>{_e(title)}</h3>']
    if note:
        out.append(f'<p class="muted small">{_e(note)}</p>')
    out.append(
        '<table class="bars"><thead><tr><th>Group</th><th class="w">Attack success rate</th>'
        '<th class="num">ASR</th><th class="num">Succ./Done</th><th class="num">95% CI</th></tr></thead><tbody>'
    )
    for name, b in rows:
        w = max(0.0, min(1.0, b["asr"])) * 100
        tip = f"{name}: {_pct(b['asr'])} ({b['successes']}/{b['completed']}), errors {b['errors']}"
        out.append(
            f'<tr title="{_e(tip)}"><td class="lbl">{_e(name)}</td>'
            f'<td class="w"><div class="track"><div class="bar" style="width:{w:.2f}%"></div></div></td>'
            f'<td class="num strong">{_pct(b["asr"])}</td><td class="num">{b["successes"]}/{b["completed"]}</td>'
            f'<td class="num muted ci">{_pct(b["ci95"][0])}-{_pct(b["ci95"][1])}</td></tr>'
        )
    out.append("</tbody></table></section>")
    return "".join(out)


def _heatmap(matrix: dict[str, dict[str, Any]]) -> str:
    techniques = sorted({t for row in matrix.values() for t in row})
    if not techniques:
        return ""
    out = [
        '<section class="card wide"><h3>Scenario x technique</h3>'
        '<p class="muted small">Cell = attack success rate (successes/completed). Darker is worse. '
        'Empty cells: technique not applicable to that scenario.</p><div class="scroll"><table class="heat"><thead><tr><th></th>'
    ]
    out.extend(f'<th class="rot"><span>{_e(t)}</span></th>' for t in techniques)
    out.append("</tr></thead><tbody>")
    for s in sorted(matrix):
        out.append(f'<tr><th class="lbl">{_e(s)}</th>')
        for t in techniques:
            b = matrix[s].get(t)
            if not b or not b["completed"]:
                out.append('<td class="na">-</td>')
                continue
            idx = min(len(RAMP) - 1, int(b["asr"] * (len(RAMP) - 1) + 0.5))
            ink = "#ffffff" if idx >= 7 else "#0b0b0b"
            tip = f"{s} / {t}: {_pct(b['asr'])} ({b['successes']}/{b['completed']})"
            out.append(
                f'<td title="{_e(tip)}" style="background:{RAMP[idx]};color:{ink}">'
                f'{round(b["asr"] * 100)}<span class="small">%</span></td>'
            )
        out.append("</tr>")
    out.append("</tbody></table></div></section>")
    return "".join(out)


CSS = """
:root{color-scheme:light;--bg:#f6f6f4;--surface:#fcfcfb;--border:#e4e3df;--text:#0b0b0b;--text2:#52514e;
--muted:#7a7974;--series:#2a78d6;--track:#ecebe7;--critical:#d03b3b;--good:#0ca30c;--code:#f0efec;--hl:#fde68a}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#111110;
--surface:#1a1a19;--border:#2e2e2b;--text:#ffffff;--text2:#c3c2b7;--muted:#8f8e86;--series:#3987e5;--track:#2a2a27;
--code:#232321;--hl:#7c5e00}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#111110;--surface:#1a1a19;--border:#2e2e2b;--text:#ffffff;
--text2:#c3c2b7;--muted:#8f8e86;--series:#3987e5;--track:#2a2a27;--code:#232321;--hl:#7c5e00}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:24px 16px 8px;max-width:1240px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 10px}h3{font-size:14px;margin:0 0 8px}
main{max-width:1240px;margin:0 auto;padding:0 16px 48px}.muted{color:var(--muted)}.small{font-size:12px}
.strong{font-weight:600}.meta{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--text2);font-size:13px}
.meta b{color:var(--text);font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile .v{font-size:26px;font-weight:650;letter-spacing:-.01em}.tile .k{color:var(--text2);font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;min-width:0}
.card.wide{grid-column:1/-1}.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{padding:5px 8px;text-align:left;vertical-align:middle}
thead th{color:var(--text2);font-weight:500;font-size:12px;border-bottom:1px solid var(--border)}
tbody tr+tr td,tbody tr+tr th{border-top:1px solid var(--border)}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.bars .lbl{max-width:220px;overflow-wrap:break-word}.bars .w{width:42%}
.track{height:12px;background:var(--track);border-radius:4px;overflow:hidden}
.bar{height:100%;background:var(--series);border-radius:0 4px 4px 0;min-width:0}
.heat td{text-align:center;font-variant-numeric:tabular-nums;min-width:46px;border:2px solid var(--surface)}
.heat td.na{color:var(--muted)}.heat th.lbl{white-space:nowrap;font-weight:500}
.heat th.rot{height:120px;vertical-align:bottom;padding:0 2px}
.heat th.rot span{writing-mode:vertical-rl;transform:rotate(180deg);white-space:nowrap}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
input[type=search],select{background:var(--surface);color:var(--text);border:1px solid var(--border);
border-radius:6px;padding:6px 8px;font:inherit}
.cases tbody tr{cursor:pointer}.cases tbody tr:hover{background:var(--code)}
.pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:0 7px;font-size:12px;
color:var(--text2);margin:1px 2px 1px 0}.pill.crit{border-color:var(--critical);color:var(--critical)}
.ok{color:var(--good)}.bad{color:var(--critical)}
#viewer{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:flex-start;justify-content:center;
padding:24px 12px;overflow:auto;z-index:10}
#viewer.open{display:flex}#panel{background:var(--surface);color:var(--text);border-radius:12px;max-width:980px;
width:100%;padding:18px 20px;border:1px solid var(--border)}
#panel h3{font-size:16px}.msg{border:1px solid var(--border);border-radius:8px;margin:8px 0;overflow:hidden}
.msg .role{font-size:12px;font-weight:600;padding:4px 10px;background:var(--code);color:var(--text2)}
.msg pre,.box{margin:0;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;
font:12.5px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
.msg.assistant .role{color:var(--series)}.msg.tool .role{color:var(--muted)}
mark{background:var(--hl);color:inherit}.inv{color:var(--critical);font-weight:600}
button{font:inherit;background:var(--code);color:var(--text);border:1px solid var(--border);border-radius:6px;
padding:5px 10px;cursor:pointer}
.ev{background:var(--code);border-radius:6px;padding:6px 8px;margin:4px 0}
@media (max-width:640px){.tiles{grid-template-columns:1fr 1fr}.tile .v{font-size:22px}.card{padding:12px}.bars thead{display:none}.bars tr{display:grid;grid-template-columns:1fr auto auto;align-items:center;column-gap:8px}.bars td{padding:2px 0}.bars td.lbl{grid-column:1/-1;max-width:none;padding-top:8px}.bars td.w{width:auto}.bars td.ci{display:none}.bars tbody tr+tr td{border-top:0}.bars tbody tr+tr{border-top:1px solid var(--border)}.cases th:nth-child(4),.cases td:nth-child(4){display:none}}
"""

JS = r"""
(function(){
const DATA = JSON.parse(document.getElementById('ilab-data').textContent);
const tbody = document.querySelector('#cases tbody');
const q = document.getElementById('q'), fs = document.getElementById('fscen'), fg = document.getElementById('fgoal');
const viewer = document.getElementById('viewer'), panel = document.getElementById('panel');
let reveal = false, current = null;
function el(tag, cls, text){const e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined) e.textContent=text; return e;}
function render(){
  const term=(q.value||'').toLowerCase(), sc=fs.value, gl=fg.value;
  tbody.textContent='';
  let n=0;
  for(const t of DATA.cases){
    if(sc && t.scenario!==sc) continue; if(gl && t.goal!==gl) continue;
    const hay=(t.scenario+' '+t.payload+' '+t.technique+' '+t.mutators+' '+t.violations.join(' ')).toLowerCase();
    if(term && !hay.includes(term)) continue;
    const tr=el('tr'); tr.tabIndex=0;
    tr.appendChild(el('td','',t.scenario)); tr.appendChild(el('td','',t.payload));
    tr.appendChild(el('td','',t.mutators)); tr.appendChild(el('td','',t.position));
    const v=el('td'); for(const o of t.oracles.filter(o=>o.fired)){v.appendChild(el('span','pill'+(o.severity==='critical'?' crit':''),o.id));}
    tr.appendChild(v); tr.appendChild(el('td','num',String(t.turns)));
    tr.addEventListener('click',()=>open(t)); tr.addEventListener('keydown',e=>{if(e.key==='Enter')open(t);});
    tbody.appendChild(tr); n++;
  }
  document.getElementById('ncases').textContent=n+' shown';
}
const INVIS=/[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u180e\u202a-\u202e\u2066-\u2069]|[\u{E0000}-\u{E007F}]/gu;
function showText(parent, text, canary){
  // Builds DOM nodes only (no innerHTML): highlights the canary and optionally reveals invisible characters.
  const parts=[]; let s=text||'';
  if(reveal){
    s=s.replace(INVIS, ch=>{const cp=ch.codePointAt(0); if(cp>=0xE0000) return '\u0001'+String.fromCharCode(cp-0xE0000)+'\u0002'; return '\u0001U+'+cp.toString(16).toUpperCase().padStart(4,'0')+'\u0002';});
  }
  const re=canary? new RegExp('('+canary.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi') : null;
  const segs=s.split(/(\u0001[^\u0002]*\u0002)/);
  for(const seg of segs){
    if(seg.startsWith('\u0001')){parent.appendChild(el('span','inv','\u27e8'+seg.slice(1,-1)+'\u27e9')); continue;}
    if(!re){parent.appendChild(document.createTextNode(seg)); continue;}
    const bits=seg.split(re);
    for(let i=0;i<bits.length;i++){ if(i%2===1) parent.appendChild(el('mark','',bits[i])); else if(bits[i]) parent.appendChild(document.createTextNode(bits[i])); }
  }
}
function block(title, text, canary, cls){
  const d=el('div','msg '+(cls||'')); d.appendChild(el('div','role',title)); const p=el('pre'); showText(p,text,canary); d.appendChild(p); return d;
}
function open(t){
  current=t; panel.textContent='';
  const top=el('div'); top.style.display='flex'; top.style.justifyContent='space-between'; top.style.gap='8px';
  top.appendChild(el('h3','',t.scenario+'  /  '+t.payload));
  const btns=el('div'); const rv=el('button','',reveal?'Hide invisible chars':'Reveal invisible chars');
  rv.addEventListener('click',()=>{reveal=!reveal; open(current);}); const cl=el('button','','Close');
  cl.addEventListener('click',close); btns.appendChild(rv); btns.appendChild(document.createTextNode(' ')); btns.appendChild(cl);
  top.appendChild(btns); panel.appendChild(top);
  panel.appendChild(el('p','muted small','trial '+t.trial_id+' | goal '+t.goal+' | technique '+t.technique+' | mutators '+t.mutators+' | position '+t.position+' | repeat '+t.repeat+' | canary '+t.canary+' | stop: '+t.stop_reason));
  for(const o of t.oracles.filter(o=>o.fired)){const d=el('div','ev'); d.appendChild(el('b','',o.id+' ('+o.type+', '+o.severity+')')); const p=el('pre','box'); showText(p,JSON.stringify(o.evidence,null,2),t.canary); d.appendChild(p); panel.appendChild(d);}
  const tr=DATA.transcripts[t.trial_id];
  if(!tr){panel.appendChild(el('p','muted','Transcript not embedded in this report (see transcripts.jsonl).')); viewer.classList.add('open'); return;}
  if(tr.payload_text) panel.appendChild(block('Payload (before mutation)', tr.payload_text, null, 'tool'));
  for(const m of tr.messages){
    let title=m.role; if(m.role==='tool') title='tool result: '+(m.name||'');
    const body=(m.content||'') + (m.tool_calls&&m.tool_calls.length? (m.content?'\n':'')+m.tool_calls.map(c=>'\u2192 '+c.name+' '+JSON.stringify(c.arguments,null,1)).join('\n'):'');
    panel.appendChild(block(title, body, t.canary, m.role));
  }
  viewer.classList.add('open'); panel.scrollIntoView();
}
function close(){viewer.classList.remove('open');}
viewer.addEventListener('click',e=>{if(e.target===viewer)close();});
document.addEventListener('keydown',e=>{if(e.key==='Escape')close();});
for(const s of [...new Set(DATA.cases.map(c=>c.scenario))].sort()){const o=el('option','',s); o.value=s; fs.appendChild(o);}
for(const g of [...new Set(DATA.cases.map(c=>c.goal))].sort()){const o=el('option','',g); o.value=g; fg.appendChild(o);}
[q,fs,fg].forEach(x=>x.addEventListener('input',render));
render();
})();
"""


def build_html(
    results: dict[str, Any], transcripts: dict[str, dict[str, Any]], *, max_transcripts: int = 300
) -> str:
    summary = results["summary"]
    cfg = results.get("config", {})
    ov = summary["overall"]
    cases = worst_cases(results["trials"], limit=5000)
    embedded = {
        t["trial_id"]: transcripts[t["trial_id"]]
        for t in cases[:max_transcripts]
        if t["trial_id"] in transcripts
    }
    case_rows = [
        {
            k: t[k]
            for k in (
                "trial_id",
                "scenario",
                "payload",
                "goal",
                "technique",
                "mutators",
                "position",
                "repeat",
                "canary",
                "turns",
                "stop_reason",
                "violations",
            )
        }
        | {"oracles": [o for o in t["oracles"] if o["fired"]]}
        for t in cases
    ]
    ctrl = summary.get("controls", {})
    errors = ov["errors"]
    tiles = [
        ("Attack success rate", _pct(ov["asr"]), f"95% CI {_pct(ov['ci95'][0])}-{_pct(ov['ci95'][1])}"),
        ("Successful attacks", f"{ov['successes']}", f"of {ov['completed']} completed trials"),
        ("Trials", f"{ov['trials']}", f"{errors} error(s)" if errors else "no errors"),
        (
            "Control false alarms",
            f"{ctrl.get('false_alarms', 0)}",
            f"of {ctrl.get('trials', 0)} benign control runs",
        ),
    ]
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>injectlab report - {_e(cfg.get('target', ''))}</title><style>{CSS}</style></head><body>",
        '<header><h1>injectlab - indirect prompt-injection report</h1><div class="meta">',
        f"<span>Target <b>{_e(cfg.get('target', '?'))}</b></span>",
        f"<span>Run <b>{_e(results.get('run_id', ''))}</b></span>",
        f"<span>Created <b>{_e(results.get('created_at', ''))}</b></span>",
        f"<span>Seed <b>{_e(cfg.get('seed', ''))}</b></span>",
        f"<span>Repeats <b>{_e(cfg.get('repeats', ''))}</b></span>",
        f"<span>Mutators <b>{_e(', '.join(cfg.get('mutators', [])))}</b></span>",
        f"<span>injectlab <b>{_e(results.get('injectlab_version', ''))}</b></span>",
        "</div></header><main>",
        '<div class="tiles">',
    ]
    for k, v, sub in tiles:
        parts.append(
            f'<div class="tile"><div class="k">{_e(k)}</div><div class="v">{_e(v)}</div>'
            f'<div class="muted small">{_e(sub)}</div></div>'
        )
    parts.append("</div>")
    if ctrl.get("false_alarms"):
        parts.append(
            f'<p class="bad">Oracles fired on benign control runs: {_e(", ".join(ctrl["false_alarm_oracles"]))}. '
            "Check the scenario oracles or the agent's baseline behaviour before trusting the ASR.</p>"
        )
    parts.append(
        '<p class="muted small">ASR = trials where an oracle relevant to the payload\'s goal fired, divided by '
        "completed trials (errors excluded). Scores from the built-in mock models describe the harness, not any real model.</p>"
    )
    parts.append('<h2>Breakdown</h2><div class="grid">')
    parts.append(_bars("By scenario", summary.get("by_scenario", {})))
    parts.append(_bars("By technique", summary.get("by_technique", {})))
    parts.append(_bars("By mutator chain", summary.get("by_mutators", {})))
    parts.append(_bars("By goal", summary.get("by_goal", {})))
    if len(summary.get("by_position", {})) > 1:
        parts.append(_bars("By injection position", summary["by_position"]))
    parts.append(_heatmap(summary.get("scenario_x_technique", {})))
    parts.append("</div>")
    parts.append(
        '<h2>Successful attacks (worst first)</h2><div class="card"><div class="controls">'
        '<input id="q" type="search" placeholder="Filter by payload, technique, mutator, oracle..." aria-label="Filter">'
        '<select id="fscen" aria-label="Scenario"><option value="">All scenarios</option></select>'
        '<select id="fgoal" aria-label="Goal"><option value="">All goals</option></select>'
        '<span id="ncases" class="muted small" style="align-self:center"></span></div><div class="scroll">'
        '<table id="cases" class="cases"><thead><tr><th>Scenario</th><th>Payload</th><th>Mutators</th><th>Position</th>'
        '<th>Fired oracles</th><th class="num">Turns</th></tr></thead><tbody></tbody></table></div>'
        f'<p class="muted small">Click a row for the full transcript. {len(embedded)} transcript(s) embedded; '
        "all transcripts are in transcripts.jsonl.</p></div>"
    )
    parts.append('<div id="viewer" role="dialog" aria-modal="true"><div id="panel"></div></div>')
    parts.append("</main>")
    parts.append(
        f'<script id="ilab-data" type="application/json">{_safe_json({"cases": case_rows, "transcripts": embedded})}</script>'
    )
    parts.append(f"<script>{JS}</script></body></html>")
    return "".join(parts)


def write_html_report(
    results_path: str | Path, out_path: str | Path | None = None, *, max_transcripts: int = 300
) -> Path:
    results = load_results(results_path)
    transcripts = load_transcripts(results_path)
    rp = Path(results_path)
    out = Path(out_path) if out_path else (rp if rp.is_dir() else rp.parent) / "report.html"
    out.write_text(build_html(results, transcripts, max_transcripts=max_transcripts), encoding="utf-8")
    return out
