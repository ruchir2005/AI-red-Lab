"""Existing third-party scanners (Promptfoo, Garak, PyRIT): run them and read their saved results."""
import glob
import json
import os
import shutil
import subprocess
import sys
import threading

from . import db

ROOT = db.ROOT


def _venv_bin(venv, name):
    for p in (os.path.join(ROOT, venv, "Scripts", name + ".exe"), os.path.join(ROOT, venv, "bin", name)):
        if os.path.exists(p):
            return p
    return None


def _commands():
    garak = _venv_bin(".venv-garak", "garak") or shutil.which("garak")
    garak_cmd = [garak] if garak else [sys.executable, "-m", "garak"]
    pyrit_py = _venv_bin(".venv-pyrit", "python") or sys.executable
    promptfoo = shutil.which("promptfoo")
    pf = [promptfoo] if promptfoo else [shutil.which("npx") or "npx", "--yes", "promptfoo@latest"]
    return {
        "promptfoo": pf + ["eval", "-c", "promptfooconfig-security.yaml", "-o", "results/promptfoo/security-results.json"],
        "garak": garak_cmd + ["--config", "garak-rest.json", "--target_type", "rest", "-G", "garak-rest.json",
                               "--spec", "probes.promptinject.HijackHateHumans", "--generations", "1"],
        "pyrit": [pyrit_py, "pyrit_security_tests.py"],
    }


def _read(path):
    return open(path, "rb").read().decode("utf-8", "ignore")


def evidence():
    """Summarize results already saved in results/ so the dashboard and report can include them."""
    out = {"promptfoo": {"available": False}, "pyrit": {"available": False}, "garak": {"available": False}}
    for p in (os.path.join(ROOT, "results", "promptfoo-ci", "security-results.json"),
              os.path.join(ROOT, "results", "promptfoo", "security-results.json")):
        if os.path.exists(p):
            try:
                res = json.load(open(p, encoding="utf-8"))["results"]
                st = res.get("stats", {})
                out["promptfoo"] = {"available": True, "passed": st.get("successes", 0), "failed": st.get("failures", 0),
                                    "errors": st.get("errors", 0),
                                    "tests": [{"name": r.get("testCase", {}).get("description", ""), "passed": bool(r.get("success"))}
                                              for r in res.get("results", [])]}
            except Exception:
                pass
            break
    for p in (os.path.join(ROOT, "results", "pyrit-ci", "security-tests.txt"), os.path.join(ROOT, "results", "pyrit", "security-tests.txt")):
        if os.path.exists(p):
            t = _read(p)
            out["pyrit"] = {"available": True, "blocked": t.count("ATTACK RESULT: FAILURE"), "succeeded": t.count("ATTACK RESULT: SUCCESS")}
            break
    probes = {}
    files = sorted(glob.glob(os.path.join(ROOT, "results", "garak*", "*.report.jsonl")), key=os.path.getmtime)
    for f in files:
        for line in _read(f).splitlines():
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("entry_type") == "eval":
                probes[(o["probe"], o["detector"])] = {"probe": o["probe"], "detector": o["detector"], "passed": o.get("passed", 0),
                                                       "fails": o.get("fails", 0), "total": o.get("total_evaluated", 0)}
    if probes:
        out["garak"] = {"available": True, "probes": list(probes.values())}
    return out


def _run(tid, name):
    try:
        p = subprocess.run(_commands()[name], cwd=ROOT, capture_output=True, timeout=3600)
        text = (p.stdout.decode("utf-8", "replace") + "\n" + p.stderr.decode("utf-8", "replace"))[-6000:]
        summary = f"exit code {p.returncode}"
        if name == "promptfoo":
            ev = evidence()["promptfoo"]
            if ev["available"]:
                summary = f"{ev['passed']} passed, {ev['failed']} failed, {ev['errors']} errors"
        db.ex("UPDATE tool_runs SET status='done',summary=?,output=? WHERE id=?", (summary, text, tid))
    except FileNotFoundError as e:
        db.ex("UPDATE tool_runs SET status='error',summary=?,output=? WHERE id=?", (f"not installed: {e.filename}", str(e), tid))
    except Exception as e:
        db.ex("UPDATE tool_runs SET status='error',summary='failed',output=? WHERE id=?", (str(e), tid))


def start(name):
    if name not in ("promptfoo", "garak", "pyrit"):
        return None
    tid = db.ex("INSERT INTO tool_runs(tool,status,started_at,summary,output) VALUES(?,?,?,?,?)", (name, "running", db.now(), "", ""))
    threading.Thread(target=_run, args=(tid, name), daemon=True).start()
    return tid
