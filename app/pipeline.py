"""One request through every guardrail layer: input policy -> model -> output policy."""
import time

from . import db, llm, policy


def handle(message: str, guardrails: bool = True, source: str = "api") -> dict:
    t0 = time.time()
    blocked, layer, reason, response, error = False, None, "", "", None
    if guardrails:
        blocked, layer, reason = policy.check_input(message)
        if blocked:
            response = policy.message_for(layer)
    if not blocked:
        try:
            response = llm.complete(message)
        except Exception as e:
            error = str(e)
            response = f"[model error: {e}]"
        if guardrails and error is None:
            blocked, layer, reason = policy.check_output(response)
            if blocked:
                response = policy.message_for(layer)
    db.ex("INSERT INTO events(ts,source,blocked,layer,reason,snippet) VALUES(?,?,?,?,?,?)",
          (db.now(), source, int(blocked), layer, reason, message[:120]))
    return {"response": response, "blocked": blocked, "layer": layer, "reason": reason, "error": error,
            "backend": llm.backend(), "latency_ms": int((time.time() - t0) * 1000)}
