"""
OpenAI-compatible API emulator for InferD.

Port 8000, behind Nginx (:443 TLS). Handles the core model-serving
surface - the highest-traffic capture target.

Auth flow:
    - No Authorization header          → 401, logged
    - Header present, valid format     → logged; if honeytoken → 200,
                                         else → 401 (realistic OpenAI behaviour)
    - Honeytoken key                   → full session capture, 200 response

Capture classes:
    /v1/chat/completions  → key stuffing, prompt injection, jailbreak
    /v1/models            → model enumeration (probe pattern H1)
    /v1/embeddings        → embedding exfiltration, RAG pipeline probing
    /v1/moderations       → always returns clean (log what they're testing)
    /v1/completions       → legacy API probing
"""

import hashlib
import json
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.auth import check_honeytoken, openai_auth_error, parse_auth_header
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_chat_content, sample_chat_completion, sample_embedding
from honeypot.core.streaming import openai_sse_stream

router = APIRouter()

# Fake model catalogue

_MODELS = [
    # OpenAI - flagship chat
    "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
    "gpt-4o", "gpt-4o-mini",
    "gpt-4-turbo", "gpt-4",
    "gpt-3.5-turbo", "gpt-3.5-turbo-16k",
    # OpenAI - reasoning
    "o4-mini", "o3", "o3-mini", "o1", "o1-mini",
    # OpenAI - embeddings / moderation / media
    "text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002",
    "text-moderation-latest", "text-moderation-stable",
    "whisper-1", "dall-e-3", "tts-1", "tts-1-hd",
    # Anthropic (surfaced here for proxy/gateway realism)
    "claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-3-5",
    "claude-3-7-sonnet-20250219",
    "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    # Mistral (OpenAI-compatible; attackers often probe via /v1/models)
    "mistral-large-latest", "mistral-small-latest", "open-mixtral-8x7b",
    # Google (via proxy)
    "gemini-2.5-pro-preview-05-06", "gemini-2.0-flash", "gemini-1.5-pro-002",
    # Meta / open-source (common in proxy/gateway setups)
    "meta-llama/Llama-3.3-70B-Instruct",
    "meta-llama/Llama-3.1-8B-Instruct",
    "deepseek-ai/DeepSeek-R1",
    "deepseek-ai/DeepSeek-V3",
]


def _model_obj(model_id: str) -> dict:
    return {
        "id": model_id,
        "object": "model",
        "created": 1706745938,
        "owned_by": "openai",
        "permission": [],
        "root": model_id,
        "parent": None,
    }


# Helper: build and log EventRecord

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
        service="openai",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=request.headers.get("x-tls-cipher"),
        tls_protocol=request.headers.get("x-tls-protocol"),
        request_size_bytes=len(body),
        auth_key_prefix=auth_prefix,
        auth_key_hash=auth_hash,
        auth_key_raw=auth_raw,
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
    )
    await logger.log_event(ev)


async def _auth(request: Request) -> tuple:
    """
    Parse and verify auth. Returns (auth_result, error_response | None).
    Callers check if error_response is not None and return it immediately.
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    if not header:
        return auth, JSONResponse(openai_auth_error(missing=True), status_code=401)
    if not auth.is_honeytoken:
        # Log the 401 - even failed attempts are valuable data.
        return auth, None   # Callers should still log, then return 401.
    return auth, None


# Routes

@router.get("/v1/models")
async def list_models(request: Request):
    header = request.headers.get("authorization") or request.headers.get("x-api-key")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    # Model enumeration - log even without a valid key.
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"model_list_probe": True})
    return {
        "object": "list",
        "data": [_model_obj(m) for m in _MODELS],
    }


@router.get("/v1/models/{model_id:path}")
async def get_model(model_id: str, request: Request):
    header = request.headers.get("authorization") or request.headers.get("x-api-key")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model_id, {})
    return _model_obj(model_id if model_id in _MODELS else "gpt-4o")


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    model = data.get("model", "gpt-4o")
    messages = data.get("messages", [])
    stream = data.get("stream", False)
    system_prompt = next(
        (m.get("content", "") for m in messages if m.get("role") == "system"), None
    )

    extras = {
        "message_count":    len(messages),
        "has_system_prompt": bool(system_prompt),
        "system_prompt":    system_prompt,
        "stream":           stream,
        "temperature":      data.get("temperature"),
        "max_tokens":       data.get("max_tokens"),
        "tools_requested":  json.dumps(data.get("tools", [])),
    }

    if not header:
        await _log(request, 401, None, None, None, False, None, model, extras)
        return JSONResponse(openai_auth_error(missing=True), status_code=401)

    if not auth.is_honeytoken:
        await _log(request, 401, auth.key_prefix, auth.key_hash, auth.raw_key, False, None, model, extras)
        return JSONResponse(openai_auth_error(), status_code=401)

    # Honeytoken: serve a real-looking response
    canary_token = await canary_mod.issue_and_persist(
        request.state.session_id, "openai", request.state.start_us
    )

    content = sample_chat_content(canary_token=canary_token)
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               True, auth.honeytoken_id, model, extras)

    if stream:
        cid = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        created = int(time.time())
        return StreamingResponse(
            openai_sse_stream(content, model, cid, created),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    resp = sample_chat_completion(model)
    resp["choices"][0]["message"]["content"] = content
    return JSONResponse(resp)


@router.post("/v1/completions")
async def completions(request: Request):
    """Legacy completions API."""
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model = data.get("model", "gpt-3.5-turbo-instruct")

    await _log(request, 200 if auth.is_honeytoken else 401,
               auth.key_prefix, auth.key_hash, auth.raw_key, auth.is_honeytoken,
               auth.honeytoken_id, model, {"prompt_len": len(data.get("prompt", ""))})

    if not auth.is_honeytoken:
        return JSONResponse(openai_auth_error(missing=not header), status_code=401)

    canary_token = await canary_mod.issue_and_persist(
        request.state.session_id, "openai", request.state.start_us
    )
    content = sample_chat_content(canary_token=canary_token)
    return JSONResponse({
        "id": f"cmpl-{uuid.uuid4().hex[:24]}",
        "object": "text_completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "text": content,
            "index": 0,
            "logprobs": None,
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": len(data.get("prompt", "").split()),
            "completion_tokens": len(content.split()),
            "total_tokens": len(data.get("prompt", "").split()) + len(content.split()),
        },
    })


@router.post("/v1/embeddings")
async def embeddings(request: Request):
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    input_text = data.get("input", "")
    if isinstance(input_text, list):
        input_text = " ".join(str(i) for i in input_text)
    model = data.get("model", "text-embedding-3-small")
    dims = 1536 if "small" in model or "ada" in model else 3072

    await _log(request, 200 if auth.is_honeytoken else 401,
               auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {"input_length": len(input_text), "dims": dims})

    if not auth.is_honeytoken:
        return JSONResponse(openai_auth_error(missing=not header), status_code=401)

    vec = sample_embedding(dims)
    return JSONResponse({
        "object": "list",
        "data": [{"object": "embedding", "embedding": vec, "index": 0}],
        "model": model,
        "usage": {"prompt_tokens": len(input_text.split()), "total_tokens": len(input_text.split())},
    })


@router.post("/v1/moderations")
async def moderations(request: Request):
    """Always returns clean - log what content they're trying to moderate."""
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    input_text = data.get("input", "")

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, "text-moderation-latest",
               {"input_length": len(str(input_text))})

    return JSONResponse({
        "id": f"modr-{uuid.uuid4().hex[:24]}",
        "model": "text-moderation-latest",
        "results": [{
            "flagged": False,
            "categories": {k: False for k in [
                "sexual", "hate", "harassment", "self-harm",
                "sexual/minors", "hate/threatening", "violence/graphic",
                "self-harm/intent", "self-harm/instructions",
                "harassment/threatening", "violence",
            ]},
            "category_scores": {k: round(random.uniform(0.0001, 0.005), 6) for k in [
                "sexual", "hate", "harassment", "self-harm",
                "sexual/minors", "hate/threatening", "violence/graphic",
                "self-harm/intent", "self-harm/instructions",
                "harassment/threatening", "violence",
            ]},
        }],
    })


import random  # noqa: E402 - needed by moderations above
