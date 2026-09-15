"""
HuggingFace Text Generation Inference (TGI) emulator for InferD.

Port 8080, direct (no TLS).

TGI is the most commonly self-hosted HF inference server. Users run it
with `docker run -p 8080:80 ghcr.io/huggingface/text-generation-inference`
and frequently forget to add authentication or restrict access.

Capture value:
    - HF token format (hf_[A-Za-z0-9]{34}) distinct from OpenAI tokens
    - /tokenize endpoint reveals what attackers are pre-processing
    - Model names in /info reveal what model was being served
    - Input text reveals the attacker's downstream task

Format: NDJSON streaming (not SSE), different from both OpenAI and Ollama.
"""

import json
import random
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.auth import hash_key, parse_auth_header
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_tgi_response
from honeypot.core.streaming import token_stream

router = APIRouter()

_MODEL_ID = "mistralai/Mistral-7B-Instruct-v0.3"


def _extract_hf_auth(request: Request) -> tuple[str | None, str | None, str | None]:
    """Return (prefix, hash, raw_key) for HF Bearer token, or (None, None, None)."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        key = header[7:].strip()
        if key.startswith("hf_"):
            return key[:7], hash_key(key), key
    return None, None, None


async def _log(request: Request, status: int, extras: dict) -> None:
    body = request.state.raw_body
    try:
        payload_obj = json.loads(body) if body else {}
    except Exception:
        payload_obj = {}

    prefix, khash, raw_key = _extract_hf_auth(request)
    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="tgi",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=None,
        tls_protocol=None,
        request_size_bytes=len(body),
        auth_key_prefix=prefix,
        auth_key_hash=khash,
        is_honeytoken=False,
        honeytoken_id=None,
        auth_key_raw=raw_key,
        payload_json=json.dumps(payload_obj, ensure_ascii=False),
        model_requested=_MODEL_ID,
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
    """Issue and persist a canary token for a tgi session."""
    return await canary_mod.issue_and_persist(session_id, "tgi", ts)


# Routes

@router.get("/info")
async def info(request: Request):
    await _log(request, 200, {"operation": "info"})
    return JSONResponse({
        "model_id": _MODEL_ID,
        "model_sha": "e2b70d4" + uuid.uuid4().hex[:33],
        "model_dtype": "torch.bfloat16",
        "model_device_type": "cuda",
        "model_pipeline_tag": "text-generation",
        "max_concurrent_requests": 128,
        "max_best_of": 2,
        "max_stop_sequences": 4,
        "max_input_length": 4096,
        "max_total_tokens": 8192,
        "waiting_served_ratio": 1.2,
        "max_batch_total_tokens": 16384,
        "max_waiting_tokens": 20,
        "max_batch_size": None,
        "validation_workers": 2,
        "version": "3.0.1",
        "sha": "a9c4d2f",
        "docker_label": "sha-a9c4d2f",
    })


@router.get("/health")
async def health(request: Request):
    await _log(request, 200, {"operation": "health"})
    return JSONResponse({"status": "ok"})


@router.get("/metrics")
async def metrics(request: Request):
    """Prometheus-style metrics endpoint - reveals monitoring setup."""
    await _log(request, 200, {"operation": "metrics"})
    r = random.randint
    metrics_text = f"""# HELP tgi_request_count Total number of requests
# TYPE tgi_request_count counter
tgi_request_count{{method="generate"}} {r(100,9999)}
tgi_request_count{{method="generate_stream"}} {r(50,4999)}
# HELP tgi_request_duration_seconds Request duration
# TYPE tgi_request_duration_seconds histogram
tgi_request_duration_seconds_sum {round(random.uniform(100, 9999), 2)}
tgi_request_duration_seconds_count {r(150, 14999)}
# HELP tgi_queue_size Current queue size
# TYPE tgi_queue_size gauge
tgi_queue_size {r(0, 5)}
"""
    from starlette.responses import Response
    return Response(content=metrics_text, media_type="text/plain")


@router.post("/generate")
async def generate(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    inputs = data.get("inputs", "")
    parameters = data.get("parameters", {})

    await _log(request, 200, {
        "operation":    "generate",
        "input_length": len(inputs),
        "parameters":   json.dumps(parameters),
    })

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    generated = sample_tgi_response(canary_token)
    return JSONResponse({
        "generated_text": generated,
        "details": {
            "finish_reason":    "eos_token",
            "generated_tokens": len(generated.split()),
            "seed":             None,
            "prefill":          [],
            "tokens": [
                {"id": random.randint(1000, 50000), "text": t, "logprob": round(random.uniform(-2, -0.1), 4), "special": False}
                for t in generated.split()[:5]
            ],
        },
    })


@router.post("/generate_stream")
async def generate_stream(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    inputs = data.get("inputs", "")
    await _log(request, 200, {
        "operation":    "generate_stream",
        "input_length": len(inputs),
    })

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    generated = sample_tgi_response(canary_token)

    async def _tgi_stream():
        words = generated.split()
        async for token in token_stream(generated):
            chunk = {
                "token": {
                    "id":      random.randint(1000, 50000),
                    "text":    token,
                    "logprob": round(random.uniform(-2, -0.1), 4),
                    "special": False,
                },
                "generated_text": None,
                "details":        None,
            }
            yield json.dumps(chunk) + "\n"

        # Final line with full generated text.
        final = {
            "token": {"id": 2, "text": "</s>", "logprob": 0.0, "special": True},
            "generated_text": generated,
            "details": {
                "finish_reason":    "eos_token",
                "generated_tokens": len(words),
                "seed": None,
            },
        }
        yield json.dumps(final) + "\n"

    return StreamingResponse(_tgi_stream(), media_type="application/x-ndjson")


@router.post("/tokenize")
async def tokenize(request: Request):
    """
    Tokenize endpoint - reveals what text attackers are pre-processing.
    Especially interesting if they're tokenizing prompts or system instructions.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    inputs = data.get("inputs", "")
    await _log(request, 200, {
        "operation":      "tokenize",
        "input_length":   len(inputs),
        "tokenize_input": inputs,   # Full text - reveals attacker's content.
    })

    # Return fake token list.
    words = inputs.split()
    tokens = [
        {"id": random.randint(1000, 50000), "text": w, "special": False, "start": i * 6, "stop": i * 6 + len(w)}
        for i, w in enumerate(words[:512])
    ]
    return JSONResponse(tokens)


@router.post("/decode")
async def decode(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    await _log(request, 200, {"operation": "decode"})
    ids = data.get("ids", [])
    return JSONResponse({"decoded_string": " ".join(f"token_{i}" for i in ids[:20])})


import random  # noqa: E402
