"""
Ollama REST API emulator for InferD.

Port 11434, direct (no TLS, no Nginx proxy).
This is the highest-priority surface: Shodan and Censys continuously
index port 11434. Organic scanner traffic arrives within 24 hours of
deployment with zero active seeding.

Endpoints emulated:
    GET  /api/version    → version string
    GET  /api/tags       → list of fake installed models
    POST /api/show       → model metadata
    POST /api/generate   → streaming NDJSON generation
    POST /api/chat       → streaming NDJSON chat
    POST /api/pull       → fake pull progress (highest-value: logs model name)
    POST /api/push       → fake push response
    POST /api/copy       → 200 OK
    DELETE /api/delete   → 200 OK (logs what attacker assumed was installed)
    POST /api/embeddings → fake embedding vector

Research value:
    /api/pull is the single most informative endpoint: the model name
    reveals attacker intent (uncensored models, code models, specific
    instruct variants). Logged verbatim, never normalised.
"""

import json
import random
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_ollama_content, sample_ollama_response
from honeypot.core.streaming import ollama_ndjson_stream

router = APIRouter()

# Fake model registry
# Plausible set of models an attacker would expect to find on an exposed instance.

_FAKE_MODELS = [
    {"name": "llama3.3:latest",        "size": 42520653824, "family": "llama"},
    {"name": "llama3.2:latest",        "size":  1902702592, "family": "llama"},
    {"name": "llama3.2:3b",            "size":  1902702592, "family": "llama"},
    {"name": "llama3.1:8b",            "size":  4661224448, "family": "llama"},
    {"name": "llama3.1:70b",           "size": 39969128448, "family": "llama"},
    {"name": "deepseek-r1:7b",         "size":  4683055104, "family": "qwen2"},
    {"name": "deepseek-r1:14b",        "size":  9024282624, "family": "qwen2"},
    {"name": "mistral:latest",         "size":  4109854720, "family": "mistral"},
    {"name": "mistral:7b",             "size":  4109854720, "family": "mistral"},
    {"name": "phi4:latest",            "size": 14656122880, "family": "phi3"},
    {"name": "gemma3:latest",          "size":  3284815872, "family": "gemma3"},
    {"name": "gemma3:12b",             "size":  7975006208, "family": "gemma3"},
    {"name": "qwen2.5:latest",         "size":  4683743232, "family": "qwen2"},
    {"name": "qwen2.5:14b",            "size":  9034145792, "family": "qwen2"},
    {"name": "nomic-embed-text:latest","size":    274302976, "family": "nomic-bert"},
    {"name": "mxbai-embed-large:latest","size":   669827072, "family": "bert"},
]


def _model_entry(m: dict) -> dict:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
    return {
        "name":        m["name"],
        "model":       m["name"],
        "modified_at": ts,
        "size":        m["size"],
        "digest":      uuid.uuid4().hex + uuid.uuid4().hex,
        "details": {
            "parent_model":       "",
            "format":             "gguf",
            "family":             m["family"],
            "families":           [m["family"]],
            "parameter_size":     "7B",
            "quantization_level": "Q40",
        },
    }


def _done_stats() -> dict:
    return {
        "total_duration":        random.randint(1500000000, 9000000000),
        "load_duration":         random.randint(10000000, 200000000),
        "prompt_eval_count":     random.randint(10, 80),
        "prompt_eval_duration":  random.randint(50000000, 500000000),
        "eval_count":            random.randint(40, 250),
        "eval_duration":         random.randint(800000000, 5000000000),
    }


# Helper: build and log EventRecord

async def _log(request: Request, status: int, extras: dict) -> None:
    body = request.state.raw_body
    try:
        payload = json.loads(body) if body else {}
    except Exception:
        payload = {"_raw": body.decode("utf-8", errors="replace")}

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="ollama",
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
        payload_json=json.dumps(payload, ensure_ascii=False),
        model_requested=payload.get("model") if isinstance(payload, dict) else None,
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


async def _issue_canary(session_id: str, ts: int, service: str = "ollama") -> str:
    """Issue and persist a canary token. Returns the token or empty string."""
    return await canary_mod.issue_and_persist(session_id, service, ts)


# Routes

@router.get("/api/version")
async def version(request: Request):
    await _log(request, 200, {})
    return {"version": "0.6.2"}


@router.get("/api/tags")
async def tags(request: Request):
    await _log(request, 200, {})
    return {"models": [_model_entry(m) for m in _FAKE_MODELS]}


@router.post("/api/show")
async def show(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model = data.get("model", "llama3:latest")
    await _log(request, 200, {"model_show": model})
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
    return {
        "modelfile": f"# Modelfile for {model}\nFROM {model}\n",
        "parameters": "stop \"<|start_header_id|>\"\nstop \"<|end_header_id|>\"\nstop \"<|eot_id|>\"",
        "template": "{{ if .System }}<|start_header_id|>system<|end_header_id|>\n\n{{ .System }}<|eot_id|>{{ end }}",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "llama",
            "parameter_size": "8B",
            "quantization_level": "Q40",
        },
        "model_info": {
            "general.architecture": "llama",
            "general.parameter_count": 8030261248,
        },
        "modified_at": ts,
    }


@router.post("/api/generate")
async def generate(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model = data.get("model", "llama3:latest")
    stream = data.get("stream", True)

    await _log(request, 200, {
        "prompt_length": len(data.get("prompt", "")),
        "stream": stream,
    })

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    content = sample_ollama_content(canary_token)
    stats = _done_stats()

    if not stream:
        resp = sample_ollama_response(model)
        resp["response"] = content
        return JSONResponse(resp)

    return StreamingResponse(
        ollama_ndjson_stream(content, model, stats),
        media_type="application/x-ndjson",
    )


@router.post("/api/chat")
async def chat(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model = data.get("model", "llama3:latest")
    messages = data.get("messages", [])
    stream = data.get("stream", True)

    await _log(request, 200, {
        "message_count": len(messages),
        "stream": stream,
    })

    canary_token = await _issue_canary(request.state.session_id, request.state.start_us)
    content = sample_ollama_content(canary_token)
    stats = _done_stats()

    async def _chat_stream():
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
        from honeypot.core.streaming import token_stream
        from honeypot.core.config import settings
        import asyncio, math
        delay = random.lognormvariate(settings.ttft_mu, settings.ttft_sigma)
        await asyncio.sleep(max(0.05, min(delay, 4.0)))
        for word in content.split(" "):
            chunk = {"model": model, "created_at": ts,
                     "message": {"role": "assistant", "content": word + " "},
                     "done": False}
            yield json.dumps(chunk) + "\n"
            interval = random.expovariate(1.0 / settings.inter_token_mean)
            await asyncio.sleep(max(0.005, min(interval, 0.5)))
        final = {"model": model, "created_at": ts,
                 "message": {"role": "assistant", "content": ""},
                 "done": True, "done_reason": "stop"}
        final.update(stats)
        yield json.dumps(final) + "\n"

    if not stream:
        resp = sample_ollama_response(model)
        resp["message"] = {"role": "assistant", "content": content}
        return JSONResponse(resp)

    return StreamingResponse(_chat_stream(), media_type="application/x-ndjson")


@router.post("/api/pull")
async def pull(request: Request):
    """
    Fake pull progress stream.
    The model name is the primary research signal - logs verbatim.
    Attackers pulling 'dolphin-mixtral', 'wizard-uncensored', or
    specific code models reveal their intent directly.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model = data.get("model", "unknown")

    await _log(request, 200, {"pull_model": model})

    async def _pull_stream():
        stages = [
            ("pulling manifest",           0,          0),
            ("pulling ddf8c552bc4a",       1024*1024,  1024*1024*512),
            ("pulling ddf8c552bc4a",       1024*1024*512, 1024*1024*512),
            ("pulling 8c17c2ebb0ea",       1024*512,   1024*1024*100),
            ("pulling 7c23fb36d801",       1024*1024,  1024*1024*200),
            ("verifying sha256 digest",    0,          0),
            ("writing manifest",           0,          0),
            ("removing any unused layers", 0,          0),
        ]
        for status, completed, total in stages:
            line = {"status": status}
            if total:
                line["completed"] = completed
                line["total"] = total
            yield json.dumps(line) + "\n"
            await asyncio.sleep(random.uniform(0.3, 1.2))
        yield json.dumps({"status": "success"}) + "\n"

    import asyncio
    return StreamingResponse(_pull_stream(), media_type="application/x-ndjson")


@router.post("/api/push")
async def push(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    await _log(request, 200, {"push_model": data.get("model")})

    async def _push_stream():
        import asyncio
        for status in ["retrieving manifest", "pushing ddf8c552bc4a", "pushing manifest", "success"]:
            yield json.dumps({"status": status}) + "\n"
            await asyncio.sleep(random.uniform(0.2, 0.8))

    return StreamingResponse(_push_stream(), media_type="application/x-ndjson")


@router.post("/api/copy")
async def copy(request: Request):
    await _log(request, 200, {})
    return JSONResponse({}, status_code=200)


@router.delete("/api/delete")
async def delete(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model = data.get("model", "unknown")
    await _log(request, 200, {"deleted_model": model})
    return JSONResponse({}, status_code=200)


@router.post("/api/embeddings")
async def embeddings(request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    from honeypot.core.pool import sample_embedding
    await _log(request, 200, {"embed_prompt_len": len(data.get("prompt", ""))})
    # The emulator exposes only dimensions backed by a checked-in static pool.
    return {"embedding": sample_embedding(3072)}


@router.get("/api/ps")
async def ps(request: Request):
    """
    List running models - highest value for LLMjacking scanners.
    They call /api/ps to check what's loaded before deciding resource abuse.
    CNVD-2025-04094 exploit chain often starts here.
    """
    await _log(request, 200, {"operation": "ps"})
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
    # Return a fake loaded model - looks like someone is actively using this server
    return {
        "models": [
            {
                "name":        "llama3.1:8b",
                "model":       "llama3.1:8b",
                "size":        4661224448,
                "digest":      uuid.uuid4().hex + uuid.uuid4().hex,
                "details": {
                    "parent_model":       "",
                    "format":             "gguf",
                    "family":             "llama",
                    "families":           ["llama"],
                    "parameter_size":     "8B",
                    "quantization_level": "Q40",
                },
                "expires_at":  "2099-01-01T00:00:00Z",
                "size_vram":   4661224448,
            }
        ]
    }


@router.get("/api/config")
async def config(request: Request):
    """
    Configuration endpoint - targeted by CNVD-2025-04094 to enumerate
    the exposed configuration before launching further attacks.
    Returns a realistic-looking config that reveals no real system data.
    The 'allowed_origins' and 'origins' fields are the specific CVE target.
    """
    await _log(request, 200, {"operation": "config"})
    return {
        "AllowedOrigins":         ["*"],   # deliberately permissive - CVE target field
        "AllowedHosts":           [],
        "InsecureSkipVerify":     False,
        "LLMLibrary":             "",
        "Origins":                ["*"],
        "MaxRunners":             4,
        "MaxQueuedRequests":      512,
        "NumParallel":            1,
        "MaxVRAM":                0,
        "GitCommit":              "a9c4d2f",
        "GoVersion":              "go1.22.4",
        "Version":                "0.6.2",
    }


@router.get("/")
async def root(request: Request):
    """Some scanners probe the root path first."""
    await _log(request, 200, {})
    return {"message": "Ollama is running"}
