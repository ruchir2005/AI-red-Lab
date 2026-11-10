"""Policy enforcement: SQLite-backed blocklist and allow-list rules, input normalization, length limits."""
import re
import unicodedata

from . import db
from .defaults import BLOCK_MESSAGES

_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize(text: str) -> str:
    """Undo common obfuscation: unicode tricks, zero-width characters, accents, leetspeak, odd punctuation."""
    t = unicodedata.normalize("NFKD", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Mn")
    t = _ZERO_WIDTH.sub("", t).lower().translate(_LEET)
    return re.sub(r"[^a-z0-9]+", " ", t).strip()


def _rules():
    out = {}
    for r in db.q("SELECT layer, pattern FROM rules WHERE enabled=1 ORDER BY id"):
        out.setdefault(r["layer"], []).append(r["pattern"])
    return out


def _hit(pattern, candidates, flags=0):
    for c in candidates:
        try:
            if re.search(pattern, c, flags):
                return True
        except re.error:
            return False
    return False


def check_input(text: str):
    """Return (blocked, layer, reason)."""
    cfg = db.get_settings()
    if len(text) > cfg["max_input_chars"]:
        return True, "length_in", f"input longer than {cfg['max_input_chars']} characters"
    rules = _rules()
    cands = [text.lower()] + ([normalize(text)] if cfg["normalize"] else [])
    for layer in ("injection", "sensitive", "policy"):
        for p in rules.get(layer, []):
            if _hit(p, cands):
                return True, layer, f"matched rule: {p}"
    for p in rules.get("obfuscation", []):
        if _hit(p, [text]):
            return True, "obfuscation", f"matched rule: {p}"
    allow = rules.get("scope_allow", [])
    if allow and not any(_hit(p, cands) for p in allow):
        return True, "scope", "no supported topic found in the request"
    return False, None, ""


def check_output(reply: str):
    cfg = db.get_settings()
    rules = _rules()
    for layer in ("output_leak", "output_unsafe"):
        for p in rules.get(layer, []):
            if _hit(p, [reply], re.I):
                return True, layer, f"matched rule: {p}"
    if cfg["max_output_chars"] and len(reply) > cfg["max_output_chars"]:
        return True, "length_out", f"response longer than {cfg['max_output_chars']} characters"
    return False, None, ""


def message_for(layer):
    return BLOCK_MESSAGES[layer]
