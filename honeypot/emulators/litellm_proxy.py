"""
LiteLLM Proxy emulator for InferD.

Port 4000, direct (no TLS).

LiteLLM is an AI gateway that routes requests to multiple model providers.
The emulator combines gateway, key-management, SSRF-shaped, and MCP
test-connection surfaces while never forwarding attacker-controlled requests.

High-value capture surfaces:
  POST /guardrails/test_custom_code  → code-like payload corpus
  POST /key/block                    → key-management injection probe corpus
  POST /mcp-rest/test/connection     → MCP command/argument probe corpus
  POST /key/generate                 → API key management probes
  GET  /v1/models                    → provider enumeration fingerprint

Version header: litellm/1.82.6 (scanner-facing decoy metadata).
"""

import json
import random
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.auth import check_honeytoken, openai_auth_error, parse_auth_header
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_chat_content, sample_chat_completion
from honeypot.core.streaming import openai_sse_stream

router = APIRouter()

_LITELLM_VERSION = "1.82.6"

# Fake multi-provider model catalogue - reveals operator intent
_MODELS = [
    # OpenAI via LiteLLM
    "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
    # Anthropic via LiteLLM
    "claude-opus-4-5", "claude-sonnet-4-5", "claude-3-5-sonnet-20241022",
    # Google via LiteLLM
    "gemini/gemini-2.0-flash", "gemini/gemini-1.5-pro",
    # Azure OpenAI via LiteLLM
    "azure/gpt-4o", "azure/gpt-4-turbo",
    # Cohere
    "command-r-plus", "command-r",
    # Local via LiteLLM
    "ollama/llama3.1:8b", "ollama/mistral:latest",
]


def _litellm_headers() -> dict:
    return {
        "x-litellm-version": _LITELLM_VERSION,
        "server": f"litellm/{_LITELLM_VERSION}",
    }


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
        service="litellm",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=None,
        tls_protocol=None,
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


async def _issue_canary(session_id: str, ts: int) -> str:
    return await canary_mod.issue_and_persist(session_id, "litellm", ts)


# Routes - OpenAI-compatible inference

@router.get("/health")
async def health(request: Request):
    await _log(request, 200, None, None, None, False, None, None, {})
    return JSONResponse(
        {"status": "healthy", "litellm_version": _LITELLM_VERSION},
        headers=_litellm_headers(),
    )


@router.get("/v1/models")
async def list_models(request: Request):
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"operation": "model_list", "model_count": len(_MODELS)})
    now = int(time.time())
    return JSONResponse({
        "object": "list",
        "data": [
            {"id": m, "object": "model", "created": now,
             "owned_by": "litellm", "litellm_provider": m.split("/")[0] if "/" in m else "openai"}
            for m in _MODELS
        ],
    }, headers=_litellm_headers())


@router.post("/v1/chat/completions")
@router.post("/chat/completions")
async def chat_completions(request: Request):
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    model   = data.get("model", "gpt-4o")
    stream  = data.get("stream", False)
    messages = data.get("messages", [])
    prompt  = next((m.get("content", "") for m in reversed(messages)
                    if m.get("role") == "user" and isinstance(m.get("content"), str)), "")

    extras = {
        "message_count": len(messages),
        "stream":        stream,
        "provider":      model.split("/")[0] if "/" in model else "openai",
        # Capture only; it is never dereferenced, forwarded, or fetched.
        "api_base": str(data.get("api_base") or data.get("base_url") or "")[:500],
    }

    if not header:
        await _log(request, 401, None, None, None, False, None, model, extras)
        return JSONResponse(openai_auth_error(missing=True), status_code=401,
                            headers=_litellm_headers())

    if not auth.is_honeytoken:
        await _log(request, 401, auth.key_prefix, auth.key_hash, auth.raw_key,
                   False, None, model, extras)
        return JSONResponse(openai_auth_error(), status_code=401,
                            headers=_litellm_headers())

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               True, auth.honeytoken_id, model, extras)

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    content = sample_chat_content(prompt=prompt, canary_token=canary_token)

    if stream:
        cid = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        return StreamingResponse(
            openai_sse_stream(content, model, cid, int(time.time())),
            media_type="text/event-stream",
            headers={**_litellm_headers(), "Cache-Control": "no-cache"},
        )

    resp = sample_chat_completion(model)
    resp["choices"][0]["message"]["content"] = content
    return JSONResponse(resp, headers=_litellm_headers())


# Routes - Key management API

@router.post("/key/generate")
async def key_generate(request: Request):
    """Log key generation requests - reveals attacker's intended scope."""
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               False, None, None, {
                   "operation":     "key_generate",
                   "requested_models": json.dumps(data.get("models", [])),
                   "spend_limit":   data.get("max_budget"),
                   "duration":      data.get("duration"),
                   "metadata":      json.dumps(data.get("metadata", {}))[:500],
               })

    return JSONResponse({
        "key":       f"sk-litellm-{uuid.uuid4().hex[:32]}",
        "key_name":  data.get("key_alias", "generated-key"),
        "user_id":   str(uuid.uuid4()),
        "models":    data.get("models", ["gpt-4o"]),
        "expires":   None,
        "max_budget": data.get("max_budget"),
    }, headers=_litellm_headers())


@router.post("/key/block")
async def key_block(request: Request):
    """
    Key-management injection probe surface. Log the full body verbatim.
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               False, None, None, {
                   "operation": "key_block",
                   "key_probe": str(data.get("key", ""))[:500],
               })
    return JSONResponse({"blocked": True}, headers=_litellm_headers())


@router.get("/key/info/{key_id}")
async def key_info(key_id: str, request: Request):
    """Key enumeration probe - log key ID being queried."""
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               False, None, None, {
                   "operation": "key_info",
                   "queried_key": key_id[:200],
               })
    return JSONResponse({
        "key":        key_id,
        "models":     ["gpt-4o"],
        "max_budget": None,
        "spend":      round(random.uniform(0.01, 12.50), 4),
        "user_id":    str(uuid.uuid4()),
        "team_id":    None,
    }, headers=_litellm_headers())


# Routes - code and injection-shaped probe surfaces

@router.post("/guardrails/test_custom_code")
async def guardrails_test_code(request: Request):
    """
    Code-like probe surface. Log the full code payload verbatim and never evaluate it.
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    code_payload = data.get("code", "") or data.get("custom_code", "")

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               False, None, None, {
                   "operation":    "guardrails_code_test",
                   "python_code":  str(code_payload),  # full payload, never evaluated
                   "code_length":  len(str(code_payload)),
               })

    return JSONResponse({
        "success": True,
        "result":  {"passed": True, "score": 1.0, "flagged": False},
    }, headers=_litellm_headers())


@router.post("/mcp-rest/test/connection")
@router.post("/test/connection")
async def mcp_test_connection(request: Request):
    """
    MCP command-shaped probe surface. Log command, args, and env verbatim; never execute them.
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               False, None, None, {
                   "operation":   "mcp_test_connection",
                   "mcp_command": str(data.get("command", ""))[:500],
                   "mcp_args":    json.dumps(data.get("args", []))[:500],
                   "mcp_env":     json.dumps(data.get("env", {}))[:500],
                   "mcp_url":     str(data.get("url", ""))[:500],
               })

    return JSONResponse({
        "success": True,
        "tools":   [],
        "message": "Connection established",
    }, headers=_litellm_headers())


@router.post("/mcp-rest/test/tools/list")
@router.post("/test/tools/list")
async def mcp_test_tools(request: Request):
    """MCP tool list via command injection - log command verbatim."""
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               False, None, None, {
                   "operation":   "mcp_test_tools",
                   "mcp_command": str(data.get("command", ""))[:500],
                   "mcp_args":    json.dumps(data.get("args", []))[:500],
               })

    return JSONResponse({
        "tools": [
            {"name": "read_file",  "description": "Read a file from disk"},
            {"name": "write_file", "description": "Write a file to disk"},
            {"name": "execute",    "description": "Execute a shell command"},
        ]
    }, headers=_litellm_headers())


# Routes - Metrics and status

@router.get("/metrics")
async def metrics(request: Request):
    await _log(request, 200, None, None, None, False, None, None,
               {"operation": "metrics"})
    r = random.randint
    text = f"""# HELP litellm_requests_total Total API requests
# TYPE litellm_requests_total counter
litellm_requests_total {r(1000, 99999)}
# HELP litellm_spend_total Total spend in USD
# TYPE litellm_spend_total counter
litellm_spend_total {round(random.uniform(1.0, 999.99), 4)}
"""
    from starlette.responses import Response
    return Response(content=text, media_type="text/plain",
                    headers=_litellm_headers())
