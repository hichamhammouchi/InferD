"""
Google Gemini (Generative Language API) emulator for InferD.

Mounted alongside OpenAI/Anthropic on port 8000.

Protocol details:
  URL pattern : /v1beta/models/{model}:generateContent
                /v1beta/models/{model}:streamGenerateContent
                /v1/models/{model}:generateContent   (v1 alias)
  Auth        : ?key=AIza...  query param     (primary)
                x-goog-api-key: AIza...        header  (alternative)
                Authorization: Bearer ya29...  (OAuth - rare in attacker flows)
  Request body: {contents: [{role, parts: [{text}]}], generationConfig, safetySettings}
  Streaming   : SSE, unnamed data: events, each is a GenerateContentResponse chunk

URL dispatching:
  Gemini uses Google's "custom method" colon convention:
      /v1beta/models/<model-id>:generateContent
  FastAPI path parameters stop at '/', so  {model}  captures  "gemini-1.5-pro"
  and  ":generateContent"  is the literal suffix - this parses correctly in Starlette.

Capture classes:
  generateContent        → prompt injection, jailbreak, key stuffing
  streamGenerateContent  → same + streaming pipeline fingerprinting
  GET /v1beta/models     → model enumeration
  embedContent           → RAG pipeline probing via embedding extraction
  countTokens            → context window enumeration
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
    check_honeytoken,
    gemini_auth_error,
    parse_auth_header,
)
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_gemini_content, sample_embedding
from honeypot.core.streaming import gemini_sse_stream

router = APIRouter()

# Fake Gemini model catalogue

_MODELS = [
    ("gemini-2.5-pro-preview-05-06",  1746316800),
    ("gemini-2.0-flash",              1738972800),
    ("gemini-2.0-flash-lite",         1738972800),
    ("gemini-1.5-pro-002",            1727913600),
    ("gemini-1.5-flash-002",          1727913600),
    ("gemini-1.5-flash-8b",           1727913600),
    ("gemini-1.0-pro-001",            1707350400),
    ("text-embedding-004",            1714608000),
]

_SAFETY_RATINGS = [
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",  "probability": "NEGLIGIBLE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH",        "probability": "NEGLIGIBLE"},
    {"category": "HARM_CATEGORY_HARASSMENT",         "probability": "NEGLIGIBLE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT",  "probability": "NEGLIGIBLE"},
]


def _model_entry(model_id: str, version_date: int) -> dict:
    return {
        "name": f"models/{model_id}",
        "version": model_id.split("-")[-1] if model_id[-1].isdigit() else "001",
        "displayName": model_id.replace("-", " ").title(),
        "description": f"Gemini {model_id}",
        "inputTokenLimit":  1048576,
        "outputTokenLimit": 8192,
        "supportedGenerationMethods": ["generateContent", "streamGenerateContent", "countTokens"],
        "temperature": 1.0,
        "topP": 0.95,
        "topK": 64,
    }


# Auth helper

def _get_api_key(request: Request) -> str | None:
    """
    Gemini auth priority:
      1. ?key= query parameter (most common in client-side code)
      2. x-goog-api-key header
      3. Authorization: Bearer (OAuth token - treat same as raw key for honeypot)
    """
    return (
        request.query_params.get("key")
        or request.headers.get("x-goog-api-key")
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
        service="gemini",
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


def _parse_gemini_body(body: bytes) -> tuple[str, list, dict, list, str]:
    """
    Parse Gemini request body.
    Returns: (model_hint, contents, generation_config, safety_settings, system_instruction)
    """
    try:
        data = json.loads(body) if body else {}
    except Exception:
        data = {}

    contents = data.get("contents", [])
    generation_config = data.get("generationConfig", {})
    safety_settings = data.get("safetySettings", [])
    system_instruction = ""
    si = data.get("systemInstruction")
    if si:
        parts = si.get("parts", [])
        system_instruction = " ".join(p.get("text", "") for p in parts)

    return contents, generation_config, safety_settings, system_instruction


def _contents_summary(contents: list) -> dict:
    """Extract summary stats from a Gemini contents array for logging."""
    total_text = 0
    roles = []
    for c in contents:
        roles.append(c.get("role", "unknown"))
        for part in c.get("parts", []):
            total_text += len(str(part.get("text", "")))
    return {
        "turn_count": len(contents),
        "roles": json.dumps(roles),
        "total_text_chars": total_text,
    }


# Routes - model list

@router.get("/v1beta/models")
async def list_models(request: Request):
    """Gemini model enumeration - logged even without a valid key."""
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"model_list_probe": True})

    return JSONResponse({
        "models": [_model_entry(m, v) for m, v in _MODELS]
    })


@router.get("/v1beta/models/{model}")
async def get_model(model: str, request: Request):
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {"model_probe": True})

    known = next(((m, v) for m, v in _MODELS if m == model), (_MODELS[0][0], _MODELS[0][1]))
    return JSONResponse(_model_entry(*known))


# Routes - generateContent (non-streaming)

@router.post("/v1beta/models/{model}:generateContent")
@router.post("/v1/models/{model}:generateContent")
async def generate_content(model: str, request: Request):
    """
    Core Gemini inference endpoint.
    Captures: model, all turns, generation config, system instruction,
              safety override attempts, grounding config.
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    contents, generation_config, safety_settings, system_instruction = _parse_gemini_body(body)
    summary = _contents_summary(contents)

    extras = {
        **summary,
        "system_instruction_len": len(system_instruction),
        "generation_config":      json.dumps(generation_config),
        "safety_overrides":       len(safety_settings),
    }

    if not raw_key:
        await _log(request, 403, None, None, None, False, None, model, extras)
        return JSONResponse(gemini_auth_error(), status_code=403)

    if not auth.is_honeytoken:
        await _log(request, 403, auth.key_prefix, auth.key_hash, auth.raw_key, False, None, model, extras)
        return JSONResponse(gemini_auth_error(), status_code=403)

    canary_token = await canary_mod.issue_and_persist(
        request.state.session_id, "gemini", request.state.start_us
    )

    content = sample_gemini_content(canary_token)
    prompt_tokens = max(10, summary["total_text_chars"] // 4)
    output_tokens = max(10, len(content.split()))

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               True, auth.honeytoken_id, model, extras)

    return JSONResponse({
        "candidates": [
            {
                "content": {"parts": [{"text": content}], "role": "model"},
                "finishReason": "STOP",
                "index": 0,
                "safetyRatings": _SAFETY_RATINGS,
            }
        ],
        "usageMetadata": {
            "promptTokenCount":     prompt_tokens,
            "candidatesTokenCount": output_tokens,
            "totalTokenCount":      prompt_tokens + output_tokens,
        },
        "modelVersion": model,
    })


# Routes - streamGenerateContent

@router.post("/v1beta/models/{model}:streamGenerateContent")
@router.post("/v1/models/{model}:streamGenerateContent")
async def stream_generate_content(model: str, request: Request):
    """
    Streaming Gemini inference.
    Yields SSE chunks with partial GenerateContentResponse objects.
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    contents, generation_config, safety_settings, system_instruction = _parse_gemini_body(body)
    summary = _contents_summary(contents)

    extras = {
        **summary,
        "system_instruction_len": len(system_instruction),
        "generation_config":      json.dumps(generation_config),
        "safety_overrides":       len(safety_settings),
        "stream":                 True,
    }

    if not raw_key:
        await _log(request, 403, None, None, None, False, None, model, extras)
        return JSONResponse(gemini_auth_error(), status_code=403)

    if not auth.is_honeytoken:
        await _log(request, 403, auth.key_prefix, auth.key_hash, auth.raw_key, False, None, model, extras)
        return JSONResponse(gemini_auth_error(), status_code=403)

    canary_token = await canary_mod.issue_and_persist(
        request.state.session_id, "gemini", request.state.start_us
    )

    content = sample_gemini_content(canary_token)
    prompt_tokens = max(10, summary["total_text_chars"] // 4)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               True, auth.honeytoken_id, model, extras)

    return StreamingResponse(
        gemini_sse_stream(content, model, prompt_tokens),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# Routes - countTokens

@router.post("/v1beta/models/{model}:countTokens")
@router.post("/v1/models/{model}:countTokens")
async def count_tokens(model: str, request: Request):
    """
    Token counting probe - attackers use this to gauge context window fill.
    Serves any key (including invalid ones) to maximise data collection.
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    contents, _, _, _ = _parse_gemini_body(body)
    summary = _contents_summary(contents)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {**summary, "count_tokens_probe": True})

    total_chars = summary["total_text_chars"]
    token_count = max(10, total_chars // 4)
    return JSONResponse({"totalTokens": token_count})


# Routes - embedContent

@router.post("/v1beta/models/{model}:embedContent")
@router.post("/v1/models/{model}:embedContent")
async def embed_content(model: str, request: Request):
    """
    Gemini embedding endpoint.
    Captures: model, input text, task type (retrieval vs classification etc).
    Valuable: indicates RAG pipeline construction or semantic search probing.
    """
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body) if body else {}
    except Exception:
        data = {}

    content = data.get("content", {})
    parts = content.get("parts", [])
    input_text = " ".join(p.get("text", "") for p in parts)
    task_type = data.get("taskType", "")
    title = data.get("title", "")

    await _log(request, 200 if auth.is_honeytoken else 403,
               auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {
                   "input_length": len(input_text),
                   "task_type": task_type,
                   "title": title,
                   "embed_probe": True,
               })

    if not auth.is_honeytoken and raw_key:
        return JSONResponse(gemini_auth_error(), status_code=403)

    dims = 768   # Gemini text-embedding-004 produces 768-dim by default
    vec = sample_embedding(dims)

    return JSONResponse({
        "embedding": {
            "values": vec[:dims],
        }
    })


# Routes - batchEmbedContents

@router.post("/v1beta/models/{model}:batchEmbedContents")
async def batch_embed_contents(model: str, request: Request):
    """Batch embedding - log all inputs, return plausible vectors."""
    raw_key = _get_api_key(request)
    auth = parse_auth_header(raw_key)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body) if body else {}
    except Exception:
        data = {}

    requests_list = data.get("requests", [])
    total_chars = sum(
        len(" ".join(p.get("text", "") for p in r.get("content", {}).get("parts", [])))
        for r in requests_list
    )

    await _log(request, 200 if auth.is_honeytoken else 403,
               auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {"batch_count": len(requests_list), "total_chars": total_chars})

    if not auth.is_honeytoken and raw_key:
        return JSONResponse(gemini_auth_error(), status_code=403)

    dims = 768
    return JSONResponse({
        "embeddings": [
            {"values": sample_embedding(dims)[:dims]}
            for _ in requests_list
        ]
    })
