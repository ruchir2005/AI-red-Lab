"""REST API used by the React dashboard."""
import re
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from . import db, defaults, llm, pipeline, report, runner, scanners
from .attacks import ATTACKS

router = APIRouter(prefix="/api")
LAYERS = ["injection", "sensitive", "policy", "obfuscation", "scope_allow", "output_leak", "output_unsafe"]


class ChatIn(BaseModel):
    message: str
    guardrails: bool = True


class RunIn(BaseModel):
    guardrails: bool = True
    categories: Optional[list[str]] = None


class RuleIn(BaseModel):
    layer: str
    pattern: str


class RulePatch(BaseModel):
    enabled: bool


class SettingsIn(BaseModel):
    normalize: Optional[bool] = None
    max_input_chars: Optional[int] = None
    max_output_chars: Optional[int] = None


@router.get("/health")
def health():
    return {"ok": True, "model": llm.model_label(), "backend": llm.backend()}


@router.post("/chat")
def chat(b: ChatIn):
    try:
        return pipeline.handle(b.message, b.guardrails, source="playground")
    except Exception as e:
        raise HTTPException(502, str(e))


@router.get("/attacks")
def attacks():
    return [{k: a[k] for k in ("id", "category", "owasp", "severity", "benign", "must_block")} for a in ATTACKS]


@router.get("/rules")
def rules():
    return db.q("SELECT * FROM rules ORDER BY layer, id")


@router.post("/rules")
def add_rule(b: RuleIn):
    if b.layer not in LAYERS or not b.pattern.strip():
        raise HTTPException(400, "unknown layer or empty pattern")
    try:
        re.compile(b.pattern)
    except re.error as e:
        raise HTTPException(400, f"invalid regex: {e}")
    return {"added": db.add_rule(b.layer, b.pattern.strip(), "custom")}


@router.patch("/rules/{rid}")
def toggle_rule(rid: int, b: RulePatch):
    db.ex("UPDATE rules SET enabled=? WHERE id=?", (int(b.enabled), rid))
    return {"ok": True}


@router.delete("/rules/{rid}")
def delete_rule(rid: int):
    db.ex("DELETE FROM rules WHERE id=?", (rid,))
    return {"ok": True}


@router.get("/settings")
def get_settings():
    return db.get_settings()


@router.put("/settings")
def put_settings(b: SettingsIn):
    for k, v in b.model_dump(exclude_none=True).items():
        db.set_setting(k, int(v) if isinstance(v, bool) else v)
    return db.get_settings()


@router.post("/harden")
def harden():
    """Apply the recommended rules for the gaps the suite finds, and tighten settings."""
    added = sum(db.add_rule(layer, p, "hardening") for layer, ps in defaults.HARDENING_RULES.items() for p in ps)
    for k, v in defaults.HARDEN_SETTINGS.items():
        db.set_setting(k, v)
    return {"added": added, "settings": db.get_settings()}


@router.post("/reset-rules")
def reset_rules():
    """Remove every rule and setting change, restoring the original guardrails from app/main.py."""
    db.ex("DELETE FROM rules")
    db.ex("DELETE FROM settings")
    db.init()
    return {"ok": True}


@router.post("/runs")
def start_run(b: RunIn):
    ok, msg = llm.check()
    if not ok:
        raise HTTPException(503, msg)
    return {"id": runner.start(b.guardrails, b.categories)}


@router.get("/runs")
def list_runs():
    return db.q("SELECT * FROM runs ORDER BY id DESC LIMIT 50")


@router.get("/runs/{rid}")
def get_run(rid: int):
    runs = db.q("SELECT * FROM runs WHERE id=?", (rid,))
    if not runs:
        raise HTTPException(404, "run not found")
    return {"run": runs[0], "results": db.q("SELECT * FROM results WHERE run_id=? ORDER BY id", (rid,))}


@router.get("/runs/{rid}/report")
def get_report(rid: int, format: str = "md"):
    d = report.build(rid)
    if d is None:
        raise HTTPException(404, "run not found")
    if format == "json":
        return JSONResponse(d)
    if format == "html":
        return HTMLResponse(report.to_html(d), headers={"Content-Disposition": f'attachment; filename="redteam-report-run{rid}.html"'})
    return PlainTextResponse(report.to_markdown(d), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="redteam-report-run{rid}.md"'})


@router.get("/stats")
def stats():
    done = db.q("SELECT * FROM runs WHERE status='done' ORDER BY id")
    trend = [{"label": f"#{r['id']}", "risk": r["risk_score"], "succeeded": r["succeeded"], "blocked": r["blocked"]} for r in done[-20:]]
    latest = done[-1] if done else None
    cats = []
    if latest:
        cats = db.q("SELECT category, SUM(outcome='blocked') AS blocked, SUM(outcome='resisted') AS resisted, SUM(outcome='succeeded') AS succeeded "
                    "FROM results WHERE run_id=? AND outcome NOT IN ('answered','false_positive') GROUP BY category", (latest["id"],))
    base = next((r for r in reversed(done) if not r["guardrails"]), None)
    prot = next((r for r in reversed(done) if r["guardrails"]), None)
    return {"latest": latest, "trend": trend, "categories": cats,
            "lift": {"baseline": base["risk_score"], "protected": prot["risk_score"]} if base and prot else None,
            "running": db.q("SELECT COUNT(*) AS n FROM runs WHERE status='running'")[0]["n"],
            "events": db.q("SELECT * FROM events ORDER BY id DESC LIMIT 15"), "model": llm.model_label()}


@router.get("/scanners")
def scanner_runs():
    return db.q("SELECT * FROM tool_runs ORDER BY id DESC LIMIT 10")


@router.post("/scanners/{name}")
def run_scanner(name: str):
    tid = scanners.start(name)
    if tid is None:
        raise HTTPException(404, "unknown scanner")
    return {"id": tid}


@router.get("/evidence")
def evidence():
    return scanners.evidence()
