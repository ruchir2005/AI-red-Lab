from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

from . import api, db, llm, pipeline  # noqa: E402


@asynccontextmanager
async def lifespan(app):
    db.init()
    yield


app = FastAPI(title="Northwind Retail AI", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(api.router)


class ChatRequest(BaseModel):
    message: str


@app.get("/health")
def health():
    return {"status": "ok", "model": llm.model_label()}


@app.post("/chat")
def chat(request: ChatRequest):
    """The guarded chatbot under test. Promptfoo, Garak and PyRIT all attack this endpoint (response field: "response")."""
    try:
        res = pipeline.handle(request.message, guardrails=True, source="scanner")
    except Exception as e:
        raise HTTPException(502, f"model backend error: {e}")
    return {"response": res["response"], "blocked": res["blocked"], "layer": res["layer"]}
