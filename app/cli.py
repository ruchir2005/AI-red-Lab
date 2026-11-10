"""Run the built-in suite from the command line and write the report.

  python -m app.cli run                 # guardrails on
  python -m app.cli run --baseline      # guardrails off
  python -m app.cli run --harden        # apply recommended hardening first
  python -m app.cli run --fail-above 40 # exit 1 if risk score is above 40 (for CI)
"""
import argparse
import os
import sys

from . import api, db, llm, report, runner


def main():
    ap = argparse.ArgumentParser(prog="app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--baseline", action="store_true", help="run with guardrails off")
    r.add_argument("--harden", action="store_true", help="apply recommended hardening first")
    r.add_argument("--out", default=os.path.join(db.ROOT, "reports", "generated"))
    r.add_argument("--fail-above", type=float, default=None)
    a = ap.parse_args()
    db.init()
    ok, msg = llm.check()
    if not ok:
        print("ERROR:", msg)
        sys.exit(2)
    if a.harden:
        api.harden()
    rid = runner.run_sync(not a.baseline)
    d = report.build(rid)
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, f"run-{rid}")
    open(base + ".md", "w", encoding="utf-8").write(report.to_markdown(d))
    open(base + ".html", "w", encoding="utf-8").write(report.to_html(d))
    run = d["run"]
    print(f"Run #{rid}: guardrails {'off' if a.baseline else 'on'}, {run['attacks']} attacks | "
          f"successful {run['succeeded']}, blocked {run['blocked']}, failed checks {run['failed_checks']}, "
          f"false positives {run['false_pos']}, risk {run['risk_score']}")
    print(f"Report written to {base}.md and {base}.html")
    if run["status"] != "done":
        print(f"WARNING: run is {run['status']}: {run['errors']} requests failed with a model error ({run['note']}). Results are not valid.")
        sys.exit(2)
    if a.fail_above is not None and run["risk_score"] > a.fail_above:
        print(f"Risk score {run['risk_score']} is above the allowed {a.fail_above}.")
        sys.exit(1)


if __name__ == "__main__":
    main()
