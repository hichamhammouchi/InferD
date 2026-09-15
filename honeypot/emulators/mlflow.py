"""
MLflow experiment tracking lure for InferD.

Port 5000, direct (no TLS).

Capture classes:
    - Credential stuffing on login page
    - Experiment/run enumeration via REST API
    - Artifact download attempts (may reveal what attackers think is stored)
"""

import json
import random
import uuid
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from honeypot.core import canary as canary_mod
from honeypot.core import logger
from honeypot.core.logger import EventRecord, now_us

router = APIRouter()

_TEMPLATES = Path("/app/honeypot/templates")


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
        service="mlflow",
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


@router.get("/")
async def root(request: Request):
    await _log(request, 200, {"operation": "root"})
    p = _TEMPLATES / "mlflow.html"
    html = p.read_text() if p.exists() else "<html><body>MLflow</body></html>"
    return HTMLResponse(html)


@router.post("/login")
async def login(request: Request):
    body = request.state.raw_body
    form = body.decode("utf-8", errors="replace")
    username, password = "", ""
    for part in form.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            if k == "username":
                username = v
            elif k == "password":
                password = v

    import hashlib
    await _log(request, 302, {
        "operation":       "login_attempt",
        "username":        username,
        "password_hash":   hashlib.sha256(password.encode()).hexdigest() if password else None,
        "password_length": len(password),
    })
    return RedirectResponse(url="/", status_code=302)


@router.get("/ajax-api/2.0/mlflow/experiments/list")
async def list_experiments(request: Request):
    await _log(request, 200, {"operation": "list_experiments"})
    return JSONResponse({
        "experiments": [
            {"experiment_id": "0", "name": "Default", "artifact_location": "mlflow-artifacts:/0", "lifecycle_stage": "active"},
            {"experiment_id": "1", "name": "gpt-finetune-v3", "artifact_location": "mlflow-artifacts:/1", "lifecycle_stage": "active"},
            {"experiment_id": "2", "name": "embedding-eval", "artifact_location": "mlflow-artifacts:/2", "lifecycle_stage": "active"},
        ]
    })


@router.get("/ajax-api/2.0/mlflow/runs/search")
@router.post("/ajax-api/2.0/mlflow/runs/search")
async def search_runs(request: Request):
    await _log(request, 200, {"operation": "search_runs"})
    return JSONResponse({"runs": [], "next_page_token": None})


@router.get("/ajax-api/2.0/mlflow/artifacts/list")
async def list_artifacts(request: Request):
    run_id = request.query_params.get("run_id", "")
    await _log(request, 200, {"operation": "list_artifacts", "run_id": run_id})
    return JSONResponse({
        "root_uri": f"mlflow-artifacts:/1/{run_id}/artifacts",
        "files": [
            {"path": "model/model.pkl", "is_dir": False, "file_size": random.randint(50000000, 500000000)},
            {"path": "model/requirements.txt", "is_dir": False, "file_size": 512},
        ],
    })


@router.get("/api/2.0/mlflow/{path:path}")
@router.post("/api/2.0/mlflow/{path:path}")
async def catch_all_api(path: str, request: Request):
    await _log(request, 200, {"operation": f"api_{path.replace('/', '_')}"})
    return JSONResponse({})
