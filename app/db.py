import datetime
import os
import sqlite3

from . import defaults

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.getenv("REDTEAM_DB", os.path.join(ROOT, "redteam.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, layer TEXT NOT NULL, pattern TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1, source TEXT NOT NULL DEFAULT 'custom', UNIQUE(layer, pattern));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, created_at TEXT, status TEXT, guardrails INTEGER, normalize INTEGER, backend TEXT,
  total INTEGER DEFAULT 0, attacks INTEGER DEFAULT 0, succeeded INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, resisted INTEGER DEFAULT 0,
  false_pos INTEGER DEFAULT 0, failed_checks INTEGER DEFAULT 0, risk_score REAL DEFAULT 0, errors INTEGER DEFAULT 0, note TEXT);
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY, run_id INTEGER, attack_id TEXT, category TEXT, owasp TEXT, severity TEXT,
  prompt TEXT, response TEXT, outcome TEXT, layer TEXT, reason TEXT, checks TEXT, failed_checks INTEGER, latency_ms INTEGER);
CREATE TABLE IF NOT EXISTS tool_runs(id INTEGER PRIMARY KEY, tool TEXT, status TEXT, started_at TEXT, summary TEXT, output TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, source TEXT, blocked INTEGER, layer TEXT, reason TEXT, snippet TEXT);
"""


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def q(sql, args=()):
    c = conn()
    try:
        return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally:
        c.close()


def ex(sql, args=()):
    c = conn()
    try:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid
    finally:
        c.close()


def get_settings():
    s = dict(defaults.DEFAULT_SETTINGS)
    s.update({r["key"]: r["value"] for r in q("SELECT key, value FROM settings")})
    return {"normalize": s["normalize"] == "1", "max_input_chars": int(s["max_input_chars"]),
            "max_output_chars": int(s["max_output_chars"])}


def set_setting(key, value):
    ex("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def add_rule(layer, pattern, source="custom"):
    c = conn()
    try:
        cur = c.execute("INSERT OR IGNORE INTO rules(layer,pattern,enabled,source) VALUES(?,?,1,?)", (layer, pattern, source))
        c.commit()
        return cur.rowcount
    finally:
        c.close()


def init():
    c = conn()
    try:
        c.executescript(SCHEMA)
        cols = {r[1] for r in c.execute("PRAGMA table_info(runs)")}
        if "errors" not in cols:
            c.execute("ALTER TABLE runs ADD COLUMN errors INTEGER DEFAULT 0")
        if "note" not in cols:
            c.execute("ALTER TABLE runs ADD COLUMN note TEXT")
        c.commit()
        empty = c.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0
    finally:
        c.close()
    if empty:
        for layer, patterns in defaults.DEFAULT_RULES.items():
            for p in patterns:
                add_rule(layer, p, "default")
