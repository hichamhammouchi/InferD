"""
Jupyter Notebook server lure for InferD.

Port 8888, direct (no TLS).

Jupyter is one of the most aggressively targeted AI development services
because successful access historically implies code execution on the host.
The lure only needs to pass a 2-second automated scanner inspection.

Capture classes:
    - Token brute force / credential stuffing (token format logged)
    - Notebook path enumeration
    - Cell execution attempts (code payload logged verbatim)

Visual fidelity: static HTML matching Jupyter 7.x appearance.
No real Jupyter dependency. No real execution environment.
"""

import json
import uuid
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from honeypot.core import canary as canary_mod
from honeypot.core import logger
from honeypot.core.logger import EventRecord, now_us

router = APIRouter()

_TEMPLATES = Path("/app/honeypot/templates")

_FAKE_NOTEBOOKS = [
    {"name": "model_training.ipynb",   "path": "model_training.ipynb",   "type": "notebook"},
    {"name": "data_pipeline.ipynb",    "path": "data_pipeline.ipynb",    "type": "notebook"},
    {"name": "inference_server.ipynb", "path": "inference_server.ipynb", "type": "notebook"},
    {"name": "evaluation.ipynb",       "path": "evaluation.ipynb",       "type": "notebook"},
]


async def _log(request: Request, status: int, extras: dict) -> None:
    body = request.state.raw_body
    try:
        payload_obj = json.loads(body) if body else {}
    except Exception:
        payload_obj = {"_form": body.decode("utf-8", errors="replace")}

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="jupyter",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=None,
        tls_protocol=None,
        request_size_bytes=len(body),
        auth_key_prefix=None,
        auth_key_hash=None,
        is_honeytoken=False,
        honeytoken_id=None,
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


def _read_template(name: str) -> str:
    p = _TEMPLATES / name
    return p.read_text() if p.exists() else f"<html><body>{name}</body></html>"


# Routes

@router.get("/")
async def root(request: Request):
    await _log(request, 302, {"operation": "root_redirect"})
    return RedirectResponse(url="/tree", status_code=302)


@router.get("/login")
async def login_page(request: Request):
    await _log(request, 200, {"operation": "login_page_view"})
    return HTMLResponse(_read_template("jupyter_login.html"))


@router.post("/login")
async def login_submit(request: Request):
    body = request.state.raw_body
    form_text = body.decode("utf-8", errors="replace")

    # Extract token from form body (url-encoded: password=TOKEN or token=TOKEN).
    token = ""
    for part in form_text.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            if k.strip() in ("password", "token"):
                token = v.strip()
                break

    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest() if token else None

    await _log(request, 302, {
        "operation":         "login_attempt",
        "token_length":      len(token),
        "token_hash":        token_hash,
        "token_valid_format": len(token) == 48 and all(c in "0123456789abcdef" for c in token.lower()),
    })
    # Always "succeed" - redirect to the notebook tree.
    return RedirectResponse(url="/tree", status_code=302)


@router.get("/tree")
@router.get("/tree/{path:path}")
async def notebook_tree(request: Request, path: str = ""):
    await _log(request, 200, {"operation": "tree_view", "path": path})
    return HTMLResponse(_read_template("jupyter_tree.html"))


@router.get("/notebooks/{path:path}")
async def notebook_view(path: str, request: Request):
    await _log(request, 200, {"operation": "notebook_open", "notebook_path": path})
    return HTMLResponse(_read_template("jupyter_notebook.html"))


# REST API endpoints (accessed by Jupyter frontend JS)

@router.get("/api/contents")
@router.get("/api/contents/{path:path}")
async def api_contents(request: Request, path: str = ""):
    await _log(request, 200, {"operation": "api_contents", "path": path})
    if path and path.endswith(".ipynb"):
        # Fake notebook contents.
        return JSONResponse({
            "name": path.split("/")[-1],
            "path": path,
            "type": "notebook",
            "format": "json",
            "content": {
                "nbformat": 4,
                "nbformat_minor": 5,
                "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3"}},
                "cells": [
                    {"cell_type": "code", "source": "# Model training pipeline\nimport torch\n", "outputs": [], "execution_count": None, "metadata": {}},
                    {"cell_type": "code", "source": "model = torch.load('model.pt')\n", "outputs": [], "execution_count": None, "metadata": {}},
                ],
            },
        })
    # Directory listing.
    return JSONResponse({
        "name": path or "",
        "path": path,
        "type": "directory",
        "format": "json",
        "content": [
            {"name": nb["name"], "path": nb["path"], "type": "notebook",
             "format": None, "content": None}
            for nb in _FAKE_NOTEBOOKS
        ],
    })


@router.post("/api/kernels")
async def create_kernel(request: Request):
    await _log(request, 201, {"operation": "create_kernel"})
    kid = str(uuid.uuid4())
    return JSONResponse({
        "id": kid,
        "name": "python3",
        "last_activity": "2026-01-01T00:00:00.000000Z",
        "execution_state": "idle",
        "connections": 0,
    }, status_code=201)


@router.post("/api/kernels/{kernel_id}/execute")
async def execute_cell(kernel_id: str, request: Request):
    """
    Cell execution attempt - the highest-value capture on this surface.
    Log the full code payload.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    code = data.get("code", data.get("source", ""))
    await _log(request, 200, {
        "operation":   "execute_cell",
        "kernel_id":   kernel_id,
        "cell_content": code,   # Full code - primary capture.
        "cell_type":   "code",
    })
    return JSONResponse({
        "msg_id":   str(uuid.uuid4()),
        "msg_type": "execute_reply",
        "content":  {"status": "ok", "execution_count": 1, "user_expressions": {}},
    })


@router.get("/api/sessions")
async def list_sessions(request: Request):
    await _log(request, 200, {"operation": "list_sessions"})
    return JSONResponse([])


@router.get("/api/kernelspecs")
async def kernelspecs(request: Request):
    await _log(request, 200, {"operation": "kernelspecs"})
    return JSONResponse({
        "default": "python3",
        "kernelspecs": {
            "python3": {
                "name": "python3",
                "spec": {"display_name": "Python 3 (ipykernel)", "language": "python", "argv": []},
                "resources": {},
            }
        },
    })

