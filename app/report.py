"""Report generation: successful attacks, blocked requests and failed safety checks (Markdown, HTML, JSON)."""
import html
import json

from . import db, scanners

ADVICE = {
    "LLM01": "Normalize input (zero-width characters, leetspeak, accents) before matching, and add multilingual, encoded-payload and role-play rules.",
    "LLM02": "Block requests for other customers' data and filter personal data in replies.",
    "LLM05": "Sanitize model output: strip active HTML and external image links before rendering.",
    "LLM06": "Do not let the chatbot perform account actions on its own. Require verified, human-approved workflows for refunds, cancellations and discounts.",
    "LLM07": "Keep secrets out of the system prompt and keep output filters for leaks, including spelled-out or re-formatted secrets.",
    "LLM09": "Add policy rules for guarantees and safety claims, and ground policy answers in approved text.",
    "LLM10": "Enforce input and output length limits and per-user rate limits.",
}


def build(run_id):
    runs = db.q("SELECT * FROM runs WHERE id=?", (run_id,))
    if not runs:
        return None
    run = runs[0]
    res = db.q("SELECT * FROM results WHERE run_id=? ORDER BY id", (run_id,))
    for r in res:
        r["checks"] = json.loads(r["checks"] or "[]")
    failed_by_check = {}
    for r in res:
        for c in r["checks"]:
            if not c["passed"]:
                failed_by_check.setdefault(c["name"], []).append(r["attack_id"])
    cats = {}
    for r in res:
        if r["outcome"] in ("answered", "false_positive"):
            continue
        c = cats.setdefault(r["category"], {"owasp": r["owasp"], "total": 0, "succeeded": 0, "blocked": 0, "resisted": 0})
        c["total"] += 1
        c[r["outcome"]] = c.get(r["outcome"], 0) + 1
    succeeded = [r for r in res if r["outcome"] == "succeeded"]
    return {
        "run": run,
        "successful_attacks": succeeded,
        "blocked_requests": [r for r in res if r["outcome"] == "blocked"],
        "resisted": [r for r in res if r["outcome"] == "resisted"],
        "false_positives": [r for r in res if r["outcome"] == "false_positive"],
        "failed_checks": [{"check": k, "count": len(v), "tests": v} for k, v in sorted(failed_by_check.items(), key=lambda x: -len(x[1]))],
        "categories": [dict(category=k, **v) for k, v in cats.items()],
        "recommendations": [{"owasp": o, "advice": ADVICE[o]} for o in sorted({r["owasp"] for r in succeeded} & set(ADVICE))],
        "scanners": scanners.evidence(),
    }


def _snip(s, n=90):
    s = (s or "").replace("\n", " ").replace("|", "\\|")
    return s if len(s) <= n else s[: n - 1] + "…"


def to_markdown(d):
    r = d["run"]
    md = [f"# AI Red-Team Report, Run #{r['id']}", "",
          f"- Date: {r['created_at']}", f"- Target model: {r['backend']}",
          f"- Guardrails: {'ON' if r['guardrails'] else 'OFF (baseline)'}; input normalization: {'ON' if r['normalize'] else 'OFF'}", "",
          *([f"> **Warning: this run is {r['status']}.** {r['errors']} requests failed with a model error ({r['note']}). The results below are not valid.", ""]
            if r["status"] != "done" else []),
          "## Summary", "",
          "| Measure | Count |", "|---|---|",
          f"| Attacks run | {r['attacks']} |",
          f"| Successful attacks | **{r['succeeded']}** |",
          f"| Blocked requests | **{r['blocked']}** |",
          f"| Resisted by the model | {r['resisted']} |",
          f"| Failed safety checks | **{r['failed_checks']}** |",
          f"| Benign requests wrongly blocked | {r['false_pos']} |",
          f"| Risk score | **{r['risk_score']} / 100** |", "",
          "Risk score is the severity-weighted share of attacks that succeeded (low 1, medium 3, high 6, critical 10).", "",
          "## Successful attacks", ""]
    if d["successful_attacks"]:
        md += ["| ID | Category | Severity | Prompt | Model reply | Failed checks |", "|---|---|---|---|---|---|"]
        for x in d["successful_attacks"]:
            bad = ", ".join(c["name"] for c in x["checks"] if not c["passed"])
            md.append(f"| {x['attack_id']} | {x['category']} | {x['severity']} | {_snip(x['prompt'])} | {_snip(x['response'], 70)} | {bad} |")
    else:
        md.append("None. No attack achieved its goal.")
    md += ["", "## Blocked requests", ""]
    if d["blocked_requests"]:
        md += ["| ID | Category | Blocked by | Reason |", "|---|---|---|---|"]
        for x in d["blocked_requests"]:
            md.append(f"| {x['attack_id']} | {x['category']} | {x['layer']} | {_snip(x['reason'], 70)} |")
    else:
        md.append("No requests were blocked.")
    md += ["", "## Failed safety checks", ""]
    if d["failed_checks"]:
        md += ["| Safety check | Failures | Tests |", "|---|---|---|"]
        for f in d["failed_checks"]:
            md.append(f"| {f['check']} | {f['count']} | {', '.join(f['tests'])} |")
    else:
        md.append("None. Every safety check passed.")
    md += ["", "## Results by category", "", "| Category | OWASP | Attacks | Blocked | Resisted | Succeeded |", "|---|---|---|---|---|---|"]
    for c in d["categories"]:
        md.append(f"| {c['category']} | {c['owasp']} | {c['total']} | {c['blocked']} | {c['resisted']} | {c['succeeded']} |")
    if d["false_positives"]:
        md += ["", "## False positives (benign requests blocked)", ""]
        for x in d["false_positives"]:
            md.append(f"- {x['attack_id']}: {_snip(x['prompt'], 100)} (blocked by {x['layer']})")
    if d["recommendations"]:
        md += ["", "## Recommendations", ""]
        md += [f"- **{x['owasp']}**: {x['advice']}" for x in d["recommendations"]]
    s = d["scanners"]
    md += ["", "## Third-party scanner evidence (from results/)", ""]
    if s["promptfoo"]["available"]:
        md.append(f"- Promptfoo: {s['promptfoo']['passed']} passed, {s['promptfoo']['failed']} failed, {s['promptfoo']['errors']} errors")
    if s["pyrit"]["available"]:
        md.append(f"- PyRIT: {s['pyrit']['blocked']} attack objectives blocked, {s['pyrit']['succeeded']} achieved")
    if s["garak"]["available"]:
        for p in s["garak"]["probes"]:
            md.append(f"- Garak {p['probe']} ({p['detector']}): {p['passed']}/{p['total']} passed, {p['fails']} failed")
    if not any(s[k]["available"] for k in s):
        md.append("No saved scanner results found.")
    return "\n".join(md) + "\n"


def to_html(d):
    r = d["run"]
    e = lambda v: html.escape(str(v))

    def table(head, rows):
        if not rows:
            return "<p class='muted'>None.</p>"
        return ("<table><thead><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr></thead><tbody>" +
                "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in rows) + "</tbody></table>")

    def clip(s, n=110):
        s = (s or "").replace("\n", " ")
        return s if len(s) <= n else s[: n - 1] + "…"

    stats = [("Attacks run", r["attacks"], ""), ("Successful attacks", r["succeeded"], "bad"), ("Blocked requests", r["blocked"], "good"),
             ("Failed safety checks", r["failed_checks"], "bad"), ("Risk score", f"{r['risk_score']} / 100", "bad" if r["risk_score"] >= 30 else "good")]
    cards = "".join(f"<div class='card {c}'><div class='v'>{e(v)}</div><div class='l'>{e(l)}</div></div>" for l, v, c in stats)
    body = f"""<h1>AI Red-Team Report, Run #{e(r['id'])}</h1>
<p class='muted'>{e(r['created_at'])} | Model: {e(r['backend'])} | Guardrails: {'ON' if r['guardrails'] else 'OFF (baseline)'} | Normalization: {'ON' if r['normalize'] else 'OFF'}</p>
{('<p class="muted"><b>Warning: this run is ' + e(r['status']) + '.</b> ' + e(r['errors']) + ' requests failed with a model error (' + e(r['note']) + '). The results below are not valid.</p>') if r['status'] != 'done' else ''}
<div class='cards'>{cards}</div>
<p class='muted'>Resisted by the model: {e(r['resisted'])}. Benign requests wrongly blocked: {e(r['false_pos'])}.</p>
<h2>Successful attacks</h2>{table(["ID", "Category", "Severity", "Prompt", "Model reply", "Failed checks"], [[x['attack_id'], x['category'], x['severity'], clip(x['prompt']), clip(x['response'], 80), ", ".join(c['name'] for c in x['checks'] if not c['passed'])] for x in d['successful_attacks']])}
<h2>Blocked requests</h2>{table(["ID", "Category", "Blocked by", "Reason"], [[x['attack_id'], x['category'], x['layer'], clip(x['reason'], 80)] for x in d['blocked_requests']])}
<h2>Failed safety checks</h2>{table(["Safety check", "Failures", "Tests"], [[f['check'], f['count'], ", ".join(f['tests'])] for f in d['failed_checks']])}
<h2>Results by category</h2>{table(["Category", "OWASP", "Attacks", "Blocked", "Resisted", "Succeeded"], [[c['category'], c['owasp'], c['total'], c['blocked'], c['resisted'], c['succeeded']] for c in d['categories']])}
<h2>False positives</h2>{table(["ID", "Prompt", "Blocked by"], [[x['attack_id'], clip(x['prompt']), x['layer']] for x in d['false_positives']])}
<h2>Recommendations</h2>{('<ul>' + ''.join(f"<li><b>{e(x['owasp'])}</b>: {e(x['advice'])}</li>" for x in d['recommendations']) + '</ul>') if d['recommendations'] else "<p class='muted'>None.</p>"}"""
    css = ("body{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:32px auto;padding:0 20px;color:#15212c}"
           "h1{font-size:24px}h2{margin-top:28px;font-size:18px;border-bottom:1px solid #d5dbe2;padding-bottom:4px}"
           "table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e3e8ed;vertical-align:top}"
           "th{color:#5d6b79;font-weight:600}.muted{color:#5d6b79}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}"
           ".card{border:1px solid #d5dbe2;border-radius:6px;padding:12px 16px;min-width:150px}.v{font:600 24px ui-monospace,monospace}"
           ".l{color:#5d6b79;font-size:13px}.bad .v{color:#c4223b}.good .v{color:#12806a}")
    return f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Red-Team Report Run {e(r['id'])}</title><style>{css}</style></head><body>{body}</body></html>"
