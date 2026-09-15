"""
vLLM inference server emulator for InferD.

Port 8001, direct (no TLS).

vLLM exposes an OpenAI-compatible API but is distinct from the generic
OpenAI emulator on port 8000. Separate port lets us distinguish vLLM-specific
scanner populations from generic OpenAI key stuffers.

vLLM-specific capture value:
  malformed prompt-embedding fields and remote video references are captured
  as probe telemetry and never deserialized or fetched.
  /tokenize       - reveals attacker's pre-processing pipeline
  /detokenize     - reveals what model they're targeting (token IDs)
  /version        - fingerprinting probe before attack

The advertised version is chosen from a range affected by the emulated
prompt-embedding and remote-video probe surfaces.
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
from honeypot.core.pool import sample_chat_content, sample_chat_completion, sample_embedding
from honeypot.core.streaming import openai_sse_stream

router = APIRouter()

_VLLM_VERSION = "0.10.2"

_MODELS = [
    "meta-llama/Llama-3.1-8B-Instruct",
    "meta-llama/Llama-3.1-70B-Instruct",
    "meta-llama/Llama-3.3-70B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "mistralai/Mixtral-8x7B-Instruct-v0.1",
    "deepseek-ai/DeepSeek-R1",
    "deepseek-ai/DeepSeek-V3",
    "Qwen/Qwen2.5-72B-Instruct",
    "microsoft/phi-4",
]

_SERVED_MODEL = _MODELS[0]


def _extract_prompt(data: dict) -> str:
    """Extract prompt text from request for dispatcher."""
    # Chat completions format
    messages = data.get("messages", [])
    if messages:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            return part.get("text", "")
    # Legacy completions format
    return data.get("prompt", "")


def _detect_cve_extras(data: dict, body: bytes) -> dict:
    """
    Detect vLLM CVE-specific probe patterns.
    Returns extras dict with CVE signal fields.
    """
    extras: dict = {}

    # CVE-2025-62164 uses the client-controlled prompt_embeds field.
    if "prompt_embeds" in data:
        pe = data["prompt_embeds"]
        extras["cve_probe_202562164"] = True
        extras["embedding_field"] = "prompt_embeds"
        extras["prompt_embeddings_len"] = len(str(pe))
        extras["prompt_embeddings_sample"] = str(pe)[:500]
    elif "prompt_embeddings" in data:
        pe = data["prompt_embeddings"]
        extras["suspicious_embedding_field"] = "prompt_embeddings"
        extras["prompt_embeddings_len"] = len(str(pe))
        extras["prompt_embeddings_sample"] = str(pe)[:500]

    # CVE-2026-22778: video_url in any message or top-level
    video_url = data.get("video_url")
    if not video_url:
        for msg in data.get("messages", []):
            content = msg.get("content", [])
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("video_url"):
                        video_url = part["video_url"]
                        break
            if video_url:
                break
    if video_url:
        extras["cve_probe_202622778"] = True
        extras["video_url_probe"] = str(video_url)[:500]  # logged, never fetched

    return extras


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
        service="vllm",
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
    return await canary_mod.issue_and_persist(session_id, "vllm", ts)


# Routes

@router.get("/version")
async def version(request: Request):
    await _log(request, 200, None, None, None, False, None, None,
               {"operation": "version_probe"})
    return {"version": _VLLM_VERSION}


@router.get("/health")
async def health(request: Request):
    await _log(request, 200, None, None, None, False, None, None, {})
    return JSONResponse({"status": "ok"})


@router.get("/metrics")
async def metrics(request: Request):
    """
    Prometheus metrics endpoint.
    Exposes realistic per-model labels so scanners cannot fingerprint this
    as a fake: real vLLM always includes model_name/engine_index labels on
    every gauge and counter.  Scrapers reading these learn:
      - which model is loaded (_SERVED_MODEL)
      - GPU memory pressure (cache usage)
      - request queue depth (timing-channel recon)
    """
    await _log(request, 200, None, None, None, False, None, None,
               {"operation": "metrics_probe"})
    r   = random.randint
    rf  = random.uniform
    m   = _SERVED_MODEL
    ei  = "0"   # engine_index
    gpu_cache  = round(rf(0.18, 0.82), 4)
    cpu_cache  = round(rf(0.01, 0.12), 4)
    running    = r(0, 4)
    waiting    = r(0, 12)
    preempt    = r(0, 8)
    finished   = r(200, 4000)
    p50_e2e    = round(rf(0.4, 2.1), 4)
    p99_e2e    = round(rf(2.5, 8.0), 4)
    tpot       = round(rf(0.02, 0.09), 4)
    ttft       = round(rf(0.05, 0.35), 4)

    metrics_text = (
        f'# HELP vllm:cache_config_info Information of the LLM cache configuration\n'
        f'# TYPE vllm:cache_config_info gauge\n'
        f'vllm:cache_config_info{{model_name="{m}",engine_index="{ei}",'
        f'cache_dtype="auto",block_size="16",max_model_len="131072"}} 1.0\n'

        f'# HELP vllm:num_requests_running Number of requests currently running on GPU\n'
        f'# TYPE vllm:num_requests_running gauge\n'
        f'vllm:num_requests_running{{model_name="{m}",engine_index="{ei}"}} {running}\n'

        f'# HELP vllm:num_requests_waiting Number of requests waiting to be scheduled\n'
        f'# TYPE vllm:num_requests_waiting gauge\n'
        f'vllm:num_requests_waiting{{model_name="{m}",engine_index="{ei}"}} {waiting}\n'

        f'# HELP vllm:num_requests_swapped Number of requests swapped to CPU\n'
        f'# TYPE vllm:num_requests_swapped gauge\n'
        f'vllm:num_requests_swapped{{model_name="{m}",engine_index="{ei}"}} 0\n'

        f'# HELP vllm:gpu_cache_usage_perc GPU KV-cache usage (fraction)\n'
        f'# TYPE vllm:gpu_cache_usage_perc gauge\n'
        f'vllm:gpu_cache_usage_perc{{model_name="{m}",engine_index="{ei}"}} {gpu_cache}\n'

        f'# HELP vllm:cpu_cache_usage_perc CPU KV-cache usage (fraction)\n'
        f'# TYPE vllm:cpu_cache_usage_perc gauge\n'
        f'vllm:cpu_cache_usage_perc{{model_name="{m}",engine_index="{ei}"}} {cpu_cache}\n'

        f'# HELP vllm:num_preemptions_total Total number of preemption events\n'
        f'# TYPE vllm:num_preemptions_total counter\n'
        f'vllm:num_preemptions_total{{model_name="{m}",engine_index="{ei}"}} {preempt}\n'

        f'# HELP vllm:request_success_total Total number of successful requests\n'
        f'# TYPE vllm:request_success_total counter\n'
        f'vllm:request_success_total{{model_name="{m}",engine_index="{ei}",'
        f'finished_reason="stop"}} {finished}\n'

        f'# HELP vllm:e2e_request_latency_seconds End-to-end request latency in seconds\n'
        f'# TYPE vllm:e2e_request_latency_seconds histogram\n'
        f'vllm:e2e_request_latency_seconds_sum{{model_name="{m}",engine_index="{ei}"}} '
        f'{round(finished * p50_e2e, 2)}\n'
        f'vllm:e2e_request_latency_seconds_count{{model_name="{m}",engine_index="{ei}"}} '
        f'{finished}\n'
        f'vllm:e2e_request_latency_seconds_bucket{{model_name="{m}",engine_index="{ei}",'
        f'le="1.0"}} {int(finished * 0.6)}\n'
        f'vllm:e2e_request_latency_seconds_bucket{{model_name="{m}",engine_index="{ei}",'
        f'le="5.0"}} {int(finished * 0.95)}\n'
        f'vllm:e2e_request_latency_seconds_bucket{{model_name="{m}",engine_index="{ei}",'
        f'le="+Inf"}} {finished}\n'

        f'# HELP vllm:time_per_output_token_seconds Time per output token\n'
        f'# TYPE vllm:time_per_output_token_seconds histogram\n'
        f'vllm:time_per_output_token_seconds_sum{{model_name="{m}",engine_index="{ei}"}} '
        f'{round(finished * 200 * tpot, 2)}\n'
        f'vllm:time_per_output_token_seconds_count{{model_name="{m}",engine_index="{ei}"}} '
        f'{finished * 200}\n'

        f'# HELP vllm:time_to_first_token_seconds Time to first token\n'
        f'# TYPE vllm:time_to_first_token_seconds histogram\n'
        f'vllm:time_to_first_token_seconds_sum{{model_name="{m}",engine_index="{ei}"}} '
        f'{round(finished * ttft, 2)}\n'
        f'vllm:time_to_first_token_seconds_count{{model_name="{m}",engine_index="{ei}"}} '
        f'{finished}\n'
    )

    from starlette.responses import Response
    return Response(content=metrics_text, media_type="text/plain; version=0.0.4")


@router.get("/v1/models")
async def list_models(request: Request):
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"operation": "model_list"})
    now = int(time.time())
    return {
        "object": "list",
        "data": [
            {
                "id": m, "object": "model",
                "created": now - random.randint(0, 86400 * 30),
                "owned_by": "vllm",
                "root": m, "parent": None,
                "max_model_len": 131072,
                "permission": [],
            }
            for m in _MODELS
        ],
    }


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

    model   = data.get("model", _SERVED_MODEL)
    stream  = data.get("stream", False)
    prompt  = _extract_prompt(data)
    cve_extras = _detect_cve_extras(data, body)

    extras = {
        "message_count": len(data.get("messages", [])),
        "stream":        stream,
        "model":         model,
        **cve_extras,
    }

    # vLLM serves without auth by default - log all requests, respond to all
    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model, extras)

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    content = sample_chat_content(prompt=prompt, canary_token=canary_token)

    if stream:
        cid = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        return StreamingResponse(
            openai_sse_stream(content, model, cid, int(time.time())),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                     "server": f"vllm/{_VLLM_VERSION}"},
        )

    resp = sample_chat_completion(model)
    resp["choices"][0]["message"]["content"] = content
    return JSONResponse(resp, headers={"server": f"vllm/{_VLLM_VERSION}"})


@router.post("/v1/completions")
async def completions(request: Request):
    """
    Legacy completions, including client-controlled prompt-embedding probe fields.
    vLLM does NOT require auth by default.
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    model      = data.get("model", _SERVED_MODEL)
    prompt_txt = data.get("prompt", "")
    cve_extras = _detect_cve_extras(data, body)

    extras = {
        "prompt_len": len(str(prompt_txt)),
        **cve_extras,
    }

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model, extras)

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    content = sample_chat_content(prompt=str(prompt_txt)[:200], canary_token=canary_token)

    return JSONResponse({
        "id":      f"cmpl-{uuid.uuid4().hex[:24]}",
        "object":  "text_completion",
        "created": int(time.time()),
        "model":   model,
        "choices": [{
            "text":          content,
            "index":         0,
            "logprobs":      None,
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens":     len(str(prompt_txt).split()),
            "completion_tokens": len(content.split()),
            "total_tokens":      len(str(prompt_txt).split()) + len(content.split()),
        },
    }, headers={"server": f"vllm/{_VLLM_VERSION}"})


@router.post("/tokenize")
async def tokenize(request: Request):
    """Reveals what text attacker is pre-processing."""
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    prompt = data.get("prompt", "") or data.get("text", "")
    await _log(request, 200, None, None, None, False, None,
               data.get("model", _SERVED_MODEL),
               {"operation": "tokenize", "input_len": len(prompt),
                "tokenize_input": prompt})
    words = str(prompt).split()
    return {
        "tokens": [random.randint(1000, 50000) for _ in words[:512]],
        "count":  len(words),
    }


@router.post("/detokenize")
async def detokenize(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    ids = data.get("tokens", [])
    await _log(request, 200, None, None, None, False, None, None,
               {"operation": "detokenize", "token_count": len(ids)})
    return {"prompt": " ".join(f"token{i}" for i in ids[:100])}


# /v1/embeddings

@router.post("/v1/embeddings")
async def embeddings(request: Request):
    """
    vLLM embedding endpoint - served without auth by default.

    Capture value:
      - input text reveals what the attacker is trying to embed
        (RAG pipeline construction, semantic search, document indexing)
      - model_requested reveals expected embedding model
        (often the same model used for inference, indicating single-model deployments)
      - encoding_format reveals downstream vector store format (float vs base64)
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    model = data.get("model", _SERVED_MODEL)
    raw_input = data.get("input", "")
    encoding_format = data.get("encoding_format", "float")

    if isinstance(raw_input, list):
        inputs = [str(i) for i in raw_input]
    else:
        inputs = [str(raw_input)]

    total_chars = sum(len(t) for t in inputs)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, model,
               {
                   "operation":       "embeddings",
                   "input_count":     len(inputs),
                   "total_chars":     total_chars,
                   "encoding_format": encoding_format,
                   "input_sample":    inputs[0][:300] if inputs else "",
               })

    # Use the checked-in 3072-dimension static pool. Do not synthesize vectors
    # for an unsupported model dimension: that would break reproducibility.
    dims = 3072
    prompt_tokens = max(1, total_chars // 4)

    return JSONResponse(
        {
            "object": "list",
            "data": [
                {
                    "object":    "embedding",
                    "embedding": sample_embedding(dims),
                    "index":     i,
                }
                for i, _ in enumerate(inputs)
            ],
            "model": model,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "total_tokens":  prompt_tokens,
            },
        },
        headers={"server": f"vllm/{_VLLM_VERSION}"},
    )


# /v1/lora_modules

@router.get("/v1/lora_modules")
async def list_lora_modules(request: Request):
    """
    vLLM LoRA adapter management endpoint.

    Capture value:
      - probers who hit this are looking for fine-tuned model adapters,
        indicating they expect a customised deployment (enterprise/research target)
      - attackers targeting CVE-class LoRA loading bugs will probe here first
        before attempting a malicious adapter injection
      - presence of this endpoint in a scan confirms the prober has
        vLLM-specific knowledge (not a generic OpenAI key-stuffer)
    """
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)

    await _log(request, 200, auth.key_prefix, auth.key_hash, auth.raw_key,
               auth.is_honeytoken, auth.honeytoken_id, None,
               {"operation": "lora_list_probe"})

    # Expose a plausible LoRA adapter to make the deployment look real
    return JSONResponse(
        [
            {
                "lora_name":    "assistant-v1",
                "lora_path":    "/models/lora/assistant-v1",
                "base_model":   _SERVED_MODEL,
                "rank":         16,
                "alpha":        32,
                "target_modules": ["q_proj", "v_proj"],
                "loaded":       True,
                "slot":         0,
            }
        ],
        headers={"server": f"vllm/{_VLLM_VERSION}"},
    )
