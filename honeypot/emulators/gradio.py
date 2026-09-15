"""
Gradio model demo lure for InferD.

Port 7860, direct (no TLS).

Gradio is the de facto standard for sharing ML model demos. Port 7860
is its default and is continuously indexed by Shodan.

Capture classes:
    - Prompt submissions to the fake model input (opportunistic jailbreaks,
      prompt injection attempts, test prompts revealing attacker tooling)
    - Session enumeration
"""

import json
import random
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_chat_content

router = APIRouter()

_TEMPLATES = Path("/app/honeypot/templates")


async def _log(request: Request, status: int, extras: dict) -> None:
    body = request.state.raw_body
    try:
        payload_obj = json.loads(body) if body else {}
    except Exception:
        payload_obj = {}

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="gradio",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=None, tls_protocol=None,
        request_size_bytes=len(body),
        auth_key_prefix=None, auth_key_hash=None,
        is_honeytoken=False, honeytoken_id=None,
        payload_json=json.dumps(payload_obj, ensure_ascii=False),
        model_requested=None,
        response_status=status,
        response_time_ms=(now_us() - request.state.start_us) / 1000,
        canary_echo_detected=bool(request.state.canary_echo),
        canary_token=request.state.canary_echo,
        canary_source_session=canary_mod.lookup(request.state.canary_echo).session_id
            if request.state.canary_echo else None,
        anomaly_flags=getattr(request.state, "anomaly_flags", None),
        extras=extras,
    )
    await logger.log_event(ev)


async def _issue_canary(session_id: str, ts: int) -> str:
    """Issue and persist a canary token for a gradio session."""
    return await canary_mod.issue_and_persist(session_id, "gradio", ts)


@router.get("/")
async def root(request: Request):
    await _log(request, 200, {"operation": "root"})
    p = _TEMPLATES / "gradio.html"
    html = p.read_text() if p.exists() else "<html><body>Gradio App</body></html>"
    return HTMLResponse(html)


@router.get("/info")
async def info(request: Request):
    await _log(request, 200, {"operation": "info"})
    return JSONResponse({
        "id": str(uuid.uuid4()),
        "space_id": None,
        "mode": "interface",
        "app_id": random.randint(10000, 99999),
        "title": "LLM Inference Demo",
        "description": "Interactive LLM demo",
        "version": "5.29.0",
        "author": None,
        "show_api": True,
    })


@router.post("/run/predict")
async def predict(request: Request):
    """
    Primary capture endpoint - full prompt logged verbatim.
    Gradio's /run/predict receives {"data": ["prompt text"]} from the frontend.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    inputs = data.get("data", [])
    prompt = inputs[0] if inputs else ""
    session_hash = data.get("session_hash", str(uuid.uuid4()))

    await _log(request, 200, {
        "operation":    "predict",
        "input_prompt": prompt,    # Full text - primary capture.
        "session_hash": session_hash,
    })

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    response_text = sample_chat_content(prompt=str(prompt), canary_token=canary_token)
    return JSONResponse({
        "data":           [response_text],
        "is_generating":  False,
        "duration":       round(random.uniform(0.8, 4.2), 3),
        "average_duration": round(random.uniform(1.0, 3.5), 3),
    })


@router.post("/queue/join")
async def queue_join(request: Request):
    await _log(request, 200, {"operation": "queue_join"})
    return JSONResponse({
        "event_id":   str(uuid.uuid4()),
        "queue_size": random.randint(0, 3),
    })


@router.get("/queue/status")
async def queue_status(request: Request):
    await _log(request, 200, {"operation": "queue_status"})
    return JSONResponse({
        "queue_size": 0,
        "status":     "complete",
        "eta":        0,
        "success":    True,
        "output":     {"data": [sample_chat_content(canary_token=await _issue_canary(
            request.state.session_id, request.state.start_us
        ))]},
    })


@router.get("/config")
async def config(request: Request):
    await _log(request, 200, {"operation": "config"})
    return JSONResponse({
        "version": "5.29.0",
        "mode":    "interface",
        "components": [
            {"id": 1, "type": "textbox", "props": {"label": "Input", "placeholder": "Enter your prompt..."}},
            {"id": 2, "type": "textbox", "props": {"label": "Output"}},
            {"id": 3, "type": "button",  "props": {"value": "Submit"}},
        ],
        "dependencies": [{"targets": [1], "trigger": "click", "inputs": [1], "outputs": [2]}],
    })
