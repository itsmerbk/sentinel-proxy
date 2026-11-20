import json
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sentinel.database import get_recent_logs, get_summary_stats, init_db, log_event
from sentinel.detector import inspect_prompt, inspect_tool_call


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SentinelProxy",
    description="Real-Time LLM Tool-Call Firewall & Prompt Injection Sandbox",
    version="1.0.0",
    lifespan=lifespan,
)


class PromptRequest(BaseModel):
    session_id: str = Field(default="default-session")
    prompt: str = Field(..., min_length=1)


class ToolCallRequest(BaseModel):
    session_id: str = Field(default="default-session")
    tool_name: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


@app.post("/v1/inspect/prompt")
async def evaluate_prompt(req: PromptRequest):
    start = time.perf_counter()
    result = inspect_prompt(req.prompt)
    elapsed_ms = (time.perf_counter() - start) * 1000

    log_event(
        stage="PROMPT_INGRESS",
        target=req.session_id,
        payload_preview=req.prompt,
        decision=result.decision,
        risk_score=result.risk_score,
        matched_rules=result.matched_rules,
        latency_ms=elapsed_ms,
    )

    body = {
        "decision": result.decision,
        "risk_score": result.risk_score,
        "matched_rules": result.matched_rules,
        "latency_ms": round(elapsed_ms, 3),
    }
    status_code = 403 if result.decision == "BLOCK" else 200
    return JSONResponse(status_code=status_code, content=body)


@app.post("/v1/inspect/tool-call")
async def evaluate_tool_call(req: ToolCallRequest):
    start = time.perf_counter()
    result = inspect_tool_call(req.tool_name, req.arguments)
    elapsed_ms = (time.perf_counter() - start) * 1000

    log_event(
        stage="TOOL_EGRESS",
        target=req.tool_name,
        payload_preview=json.dumps(req.arguments),
        decision=result.decision,
        risk_score=result.risk_score,
        matched_rules=result.matched_rules,
        latency_ms=elapsed_ms,
    )

    body = {
        "decision": result.decision,
        "tool_name": req.tool_name,
        "risk_score": result.risk_score,
        "matched_rules": result.matched_rules,
        "latency_ms": round(elapsed_ms, 3),
    }
    status_code = 403 if result.decision == "BLOCK" else 200
    return JSONResponse(status_code=status_code, content=body)


@app.get("/v1/stats")
async def stats():
    return {
        "metrics": get_summary_stats(),
        "recent_events": get_recent_logs(12),
    }
