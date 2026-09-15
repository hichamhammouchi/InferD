"""
Anthropic Claude Messages API emulator for InferD.

Mounted on port 8000 alongside the OpenAI emulator - realistic because
production deployments of LiteLLM / OpenRouter / custom proxies serve both
APIs on the same host.

Anthropic-specific protocol details captured here:
  - Auth: x-api-key header (NOT Authorization: Bearer)
  - Request body: {model, messages, system, max_tokens, stream, tools, ...}
  - Streaming: typed SSE events (message_start / content_block_delta / message_stop)
  - Non-streaming: {id, type, role, content: [{type, text}], stop_reason, usage}
  - Version header: anthropic-version (e.g. "2023-06-01")
  - Beta header: anthropic-beta (signals tool use, extended context, etc.)

Capture classes:
  POST /v1/messages          → key stuffing, prompt injection, jailbreak, tool abuse
  POST /v1/messages/batches  → bulk exfiltration probes
  POST /v1/messages/count_tokens → model/context enumeration
  GET  /v1/models            → model enumeration (distinct from OpenAI catalogue)
"""

import json
import random
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.core import canary as canary_mod
from honeypot.core import logger
from honeypot.core.auth import (
    anthropic_auth_error,
    check_honeytoken,
    parse_auth_header,
)
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_anthropic_content
from honeypot.core.streaming import anthropic_sse_stream

router = APIRouter()

# Fake Claude model catalogue

_MODELS = [
    "claude-opus-4-5",
    "claude-sonnet-4-5",
    "claude-haiku-3-5",
    "claude-3-7-sonnet-20250219",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
]

_MODEL_CREATED = {
    "claude-opus-4-5":             1746057600,
    "claude-sonnet-4-5":           1746057600,
    "claude-haiku-3-5":            1729555200,
    "claude-3-7-sonnet-20250219":  1739923200,
    "claude-3-5-sonnet-20241022":  1729555200,
    "claude-3-5-haiku-20241022":   1729555200,
    "claude-3-opus-20240229":      1709164800,
    "claude-3-sonnet-20240229":    1709164800,
    "claude-3-haiku-20240307":     1709769600,
}


def _model_obj(model_id: str) -> dict:
    return {
        "id": model_id,
        "display_name": model_id.replace("-", " ").title(),
        "created_at": _MODEL_CREATED.get(model_id, 1709164800),
        "type": "model",
    }


# Auth helpers

def _get_api_key(request: Request) -> str | None:
    """
    Anthropic uses x-api-key header. Fall back to Authorization: Bearer.
    parse_auth_header() handles both - it strips 'Bearer ' if present,
    or uses the raw value as-is (x-api-key sends the key directly).
    """
    return (
        request.headers.get("x-api-key")
        or request.headers.get("authorization")
    )


# Logging helper

async def _log(
    request: Request,
    status: int,
    auth_prefix: str | None,
    auth_hash: str | None,
    auth_raw: str | None,
    is_honeytoken: bool,
    honeytoken_id: str | None,
    model: str | None,
    extras: dict,
) -> None:
    body = request.state.raw_body
    try:
        payload_obj = json.loads(body) if body else {}
    except Exception:
        payload_obj = {"_raw": body.decode("utf-8", errors="replace")}

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="anthropic",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=request.headers.get("x-tls-cipher"),
        tls_protocol=request.headers.get("x-tls-protocol"),
        request_size_bytes=len(body),
        auth_key_prefix=auth_prefix,
        auth_key_hash=auth_hash,
        is_honeytoken=is_honeytoken,
        honeytoken_id=honeytoken_id,
        payload_json=json.dumps(payload_obj, ensure_ascii=False),
        model_requested=model,
        response_status=status,
        response_time_ms=(now_us() - request.state.start_us) / 1000,
        canary_echo_detected=bool(request.state.canary_echo),
        canary_token=request.state.canary_echo,
        canary_source_session=canary_mod.lookup(request.state.canary_echo).session_id
            if request.state.canary_echo else None,
        anomaly_flags=getattr(request.state, "anomaly_flags", None),
        extras=extras,
        auth_key_raw=auth_raw,
    )
    await logger.log_event(ev)


# Routes

@router.post("/v1/messages")
async def create_message(request: Request):
    """
    Core Anthropic Messages endpoint.
    Captures: model, messages, system prompt, tools, metadata.user_id,
              anthropic-version and anthropic-beta headers (signals feature probing).
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    model = data.get("model", "claude-3-5-sonnet-20241022")
    messages = data.get("messages", [])
    system = data.get("system", "")
    stream = data.get("stream", False)
    max_tokens = data.get("max_tokens", 1024)
    tools = data.get("tools", [])
    user_id = (data.get("metadata") or {}).get("user_id")

    # Signals: what beta features is the attacker enabling?
    beta_header = request.headers.get("anthropic-beta", "")
    version_header = request.headers.get("anthropic-version", "")

    extras = {
        "message_count":        len(messages),
        "has_system":           bool(system),
        "system_length":        len(system) if system else 0,
        "stream":               stream,
        "max_tokens":           max_tokens,
        "tools_count":          len(tools),
        "tool_names":           json.dumps([t.get("name") for t in tools]),
        "metadata_user_id":     user_id,
        "anthropic_version":    version_header,
        "anthropic_beta":       beta_header,
    }

    if not raw_key:
        await _log(request, 401, None, None, None, False, None, model, extras)
        return JSONResponse(anthropic_auth_error(invalid=False), status_code=401)

    if not auth.is_honeytoken:
        await _log(request, 401, auth.key_prefix, auth.key_hash, auth.raw_key, False, None, model, extras)
        return JSONResponse(anthropic_auth_error(invalid=True), status_code=401)

    # Honeytoken: serve a real-looking response
    canary_token = await canary_mod.issue_and_persist(
        request.state.session_id, "anthropic", request.state.start_us
    )

    content = sample_anthropic_content(canary_token)
    message_id = f"msg_{uuid.uuid4().hex[:24]}"
    input_tokens = random.randint(20, max_tokens // 4)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               True, auth.honeytoken_id, model, extras)

    if stream:
        return StreamingResponse(
            anthropic_sse_stream(content, model, message_id, input_tokens),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "anthropic-ratelimit-requests-limit":      "1000",
                "anthropic-ratelimit-requests-remaining":  str(random.randint(800, 999)),
                "anthropic-ratelimit-tokens-limit":        "80000",
                "anthropic-ratelimit-tokens-remaining":    str(random.randint(60000, 79000)),
            },
        )

    output_tokens = max(10, len(content.split()))
    return JSONResponse({
        "id": message_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": content}],
        "model": model,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    }, headers={
        "anthropic-ratelimit-requests-limit":      "1000",
        "anthropic-ratelimit-requests-remaining":  str(random.randint(800, 999)),
        "anthropic-ratelimit-tokens-limit":        "80000",
        "anthropic-ratelimit-tokens-remaining":    str(random.randint(60000, 79000)),
    })


@router.post("/v1/messages/count_tokens")
async def count_tokens(request: Request):
    """
    Token counting probe - attackers use this to gauge context window usage
    before sending expensive prompts. Log the full payload.
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    model = data.get("model", "claude-3-5-sonnet-20241022")
    messages = data.get("messages", [])

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {"message_count": len(messages), "token_count_probe": True})

    if not auth.is_honeytoken and raw_key:
        return JSONResponse(anthropic_auth_error(), status_code=401)

    # Return a plausible token count based on message content lengths.
    total_chars = sum(
        len(str(m.get("content", ""))) for m in messages
    )
    input_tokens = max(10, total_chars // 4)  # rough 4 chars/token heuristic

    return JSONResponse({"input_tokens": input_tokens})


@router.post("/v1/messages/batches")
async def create_batch(request: Request):
    """
    Batch Messages API - captures bulk exfiltration attempts.
    Log all requests in the batch; return a fake batch ID immediately.
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    requests_list = data.get("requests", [])
    batch_id = f"msgbatch_{uuid.uuid4().hex[:24]}"

    await _log(request, 200 if auth.is_honeytoken else 401,
               auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"batch_size": len(requests_list), "batch_id": batch_id})

    if not raw_key:
        return JSONResponse(anthropic_auth_error(invalid=False), status_code=401)
    if not auth.is_honeytoken:
        return JSONResponse(anthropic_auth_error(), status_code=401)

    now = int(time.time())
    return JSONResponse({
        "id": batch_id,
        "type": "message_batch",
        "processing_status": "in_progress",
        "request_counts": {
            "processing": len(requests_list),
            "succeeded": 0,
            "errored": 0,
            "canceled": 0,
            "expired": 0,
        },
        "ended_at": None,
        "created_at": now,
        "expires_at": now + 86400,
        "cancel_initiated_at": None,
        "results_url": None,
    })


@router.get("/v1/messages/batches/{batch_id}")
async def get_batch(batch_id: str, request: Request):
    """Fake batch status - always returns 'ended' so callers poll once."""
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"batch_id": batch_id, "batch_status_probe": True})

    now = int(time.time())
    return JSONResponse({
        "id": batch_id,
        "type": "message_batch",
        "processing_status": "ended",
        "request_counts": {
            "processing": 0,
            "succeeded": random.randint(1, 10),
            "errored": 0,
            "canceled": 0,
            "expired": 0,
        },
        "ended_at": now - 10,
        "created_at": now - 120,
        "expires_at": now + 86280,
        "cancel_initiated_at": None,
        "results_url": f"https://api.anthropic.com/v1/messages/batches/{batch_id}/results",
    })
