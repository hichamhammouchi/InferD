"""
OpenAI Assistants API emulator for InferD.

Stateful agentic sessions - the richest single capture surface.
System prompts encode operator intent. Message threads record agent
reasoning. Tool definitions reveal planned capabilities.

State is persisted in SQLite `threads` table between requests.
Thread IDs act as the session stitching key for this surface.

Canary tokens are embedded in every fake assistant reply - any
subsequent request containing the canary string confirms LLM-mediated
processing of honeypot output (H7).
"""

import json
import time
import uuid

import asyncio

import aiosqlite
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.auth import check_honeytoken, openai_auth_error, parse_auth_header
from honeypot.core.logger import EventRecord, now_us
from honeypot.core.pool import sample_chat_content

router = APIRouter()

# Fake assistant defaults

_DEFAULT_TOOLS = [
    {"type": "code_interpreter"},
    {"type": "file_search"},
]

# Synthetic function tool calls exposed during requires_action state.
# These are the function signatures most agentic frameworks provide; exposing
# them during the requires_action window forces the agent to submit tool outputs,
# which reveals what the agent actually computed.
_FAKE_FUNCTIONS = [
    {
        "name":        "search_knowledge_base",
        "description": "Search the internal knowledge base for relevant documents.",
        "parameters": {
            "type": "object",
            "properties": {
                "query":    {"type": "string"},
                "top_k":    {"type": "integer", "default": 5},
                "filter":   {"type": "object"},
            },
            "required": ["query"],
        },
    },
    {
        "name":        "execute_action",
        "description": "Execute a named action with given parameters.",
        "parameters": {
            "type": "object",
            "properties": {
                "action":  {"type": "string"},
                "payload": {"type": "object"},
            },
            "required": ["action"],
        },
    },
    {
        "name":        "send_message",
        "description": "Send a message to a user or channel.",
        "parameters": {
            "type": "object",
            "properties": {
                "to":      {"type": "string"},
                "body":    {"type": "string"},
                "channel": {"type": "string"},
            },
            "required": ["to", "body"],
        },
    },
]

# In-memory run state machine:
# run_id → {thread_id, status, poll_count, tool_calls_pending, created_at, model, asst_id}
_run_states: dict[str, dict] = {}


def _ts() -> int:
    return int(time.time())


def _run_id() -> str:
    return f"run_{uuid.uuid4().hex[:24]}"


def _msg_id() -> str:
    return f"msg_{uuid.uuid4().hex[:24]}"


def _asst_id() -> str:
    return f"asst_{uuid.uuid4().hex[:24]}"


def _thread_id() -> str:
    return f"thread_{uuid.uuid4().hex[:24]}"


# Logging helper

async def _log(request: Request, status: int, auth, model: str | None, extras: dict) -> None:
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
        service="assistants",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=request.headers.get("x-tls-cipher"),
        tls_protocol=request.headers.get("x-tls-protocol"),
        request_size_bytes=len(body),
        auth_key_prefix=auth.key_prefix if auth else None,
        auth_key_hash=auth.key_hash if auth else None,
        is_honeytoken=auth.is_honeytoken if auth else False,
        honeytoken_id=auth.honeytoken_id if auth else None,
        auth_key_raw=auth.raw_key if auth else None,
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


async def _require_auth(request: Request):
    """Return (auth, error_response). error_response is None if auth ok."""
    header = request.headers.get("authorization")
    auth = parse_auth_header(header)
    auth = await check_honeytoken(auth)
    if not header:
        return auth, JSONResponse(openai_auth_error(missing=True), status_code=401)
    if not auth.is_honeytoken:
        return auth, JSONResponse(openai_auth_error(), status_code=401)
    return auth, None


# Thread state helpers

async def _get_thread(thread_id: str) -> dict | None:
    conn: aiosqlite.Connection = await database.get_connection()
    async with conn.execute(
        "SELECT thread_id, session_id, system_prompt, tools_declared, messages_json, canary_issued, run_count "
        "FROM threads WHERE thread_id = ?",
        (thread_id,),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return None
    return {
        "thread_id":    row[0],
        "session_id":   row[1],
        "system_prompt":row[2],
        "tools_declared":row[3],
        "messages_json": row[4],
        "canary_issued": row[5],
        "run_count":     row[6],
    }


async def _save_thread(t: dict) -> None:
    # Thread reads can immediately follow writes in the same client workflow.
    # Persist synchronously so message/run state is not stale behind the batch.
    await database.write_rows([{"table": "threads", "row": t}])


# Routes

@router.post("/v1/assistants")
async def create_assistant(request: Request):
    auth, err = await _require_auth(request)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    system_prompt = data.get("instructions", "")
    model = data.get("model", "gpt-4o")
    tools = data.get("tools", _DEFAULT_TOOLS)

    await _log(request, 200 if not err else 401, auth, model, {
        "operation": "create_assistant",
        "system_prompt": system_prompt,
        "tools_declared": json.dumps(tools),
    })
    if err:
        return err

    asst_id = _asst_id()
    return JSONResponse({
        "id": asst_id,
        "object": "assistant",
        "created_at": _ts(),
        "name": data.get("name", "Assistant"),
        "description": data.get("description"),
        "model": model,
        "instructions": system_prompt,
        "tools": tools,
        "top_p": 1.0,
        "temperature": 1.0,
        "response_format": "auto",
    })


@router.post("/v1/threads")
async def create_thread(request: Request):
    auth, err = await _require_auth(request)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    await _log(request, 200 if not err else 401, auth, None, {
        "operation": "create_thread",
    })
    if err:
        return err

    thread_id = _thread_id()
    now = now_us()

    # Issue a canary token for this thread.
    canary_token = await canary_mod.issue_and_persist(
        request.state.session_id, "assistants", now
    )

    await _save_thread({
        "thread_id":      thread_id,
        "session_id":     request.state.session_id,
        "created_at_us":  now,
        "system_prompt":  None,
        "tools_declared": None,
        "messages_json":  json.dumps([]),
        "canary_issued":  canary_token or None,
        "run_count":      0,
    })

    return JSONResponse({
        "id": thread_id,
        "object": "thread",
        "created_at": _ts(),
        "metadata": {},
        "tool_resources": {},
    })


@router.post("/v1/threads/{thread_id}/messages")
async def add_message(thread_id: str, request: Request):
    auth, err = await _require_auth(request)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    content = data.get("content", "")
    role = data.get("role", "user")

    await _log(request, 200 if not err else 401, auth, None, {
        "operation": "add_message",
        "thread_id": thread_id,
        "role": role,
        "message_content": content,  # Full content - primary payload capture.
    })
    if err:
        return err

    thread = await _get_thread(thread_id)
    if thread:
        messages = json.loads(thread.get("messages_json") or "[]")
        messages.append({"role": role, "content": content, "id": _msg_id()})
        thread["messages_json"] = json.dumps(messages)
        await _save_thread(thread)

    return JSONResponse({
        "id": _msg_id(),
        "object": "thread.message",
        "created_at": _ts(),
        "thread_id": thread_id,
        "role": role,
        "content": [{"type": "text", "text": {"value": content, "annotations": []}}],
        "status": "completed",
        "metadata": {},
    })


def _build_run_obj(run_id: str, thread_id: str, state: dict) -> dict:
    now = _ts()
    s = state["status"]
    tool_calls = state.get("tool_calls_pending", [])
    return {
        "id":            run_id,
        "object":        "thread.run",
        "created_at":    state.get("created_at", now),
        "thread_id":     thread_id,
        "assistant_id":  state.get("asst_id", _asst_id()),
        "status":        s,
        "model":         state.get("model", "gpt-4o"),
        "started_at":    state.get("created_at", now),
        "expires_at":    state.get("created_at", now) + 600,
        "cancelled_at":  None,
        "failed_at":     None,
        "completed_at":  now if s == "completed" else None,
        "last_error":    None,
        "metadata":      {},
        "usage":         {"prompt_tokens": 150, "completion_tokens": 80, "total_tokens": 230}
                         if s == "completed" else None,
        "temperature":   1.0,
        "top_p":         1.0,
        "max_prompt_tokens":       32768,
        "max_completion_tokens":   32768,
        "truncation_strategy":     {"type": "auto"},
        "response_format":         "auto",
        "tool_choice":             "auto",
        "parallel_tool_calls":     True,
        "required_action": {
            "type":             "submit_tool_outputs",
            "submit_tool_outputs": {"tool_calls": tool_calls},
        } if s == "requires_action" else None,
    }


@router.post("/v1/threads/{thread_id}/runs")
async def create_run(thread_id: str, request: Request):
    auth, err = await _require_auth(request)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    model  = data.get("model", "gpt-4o")
    stream = data.get("stream", False)
    tools  = data.get("tools", _DEFAULT_TOOLS)

    await _log(request, 200 if not err else 401, auth, model, {
        "operation": "create_run",
        "thread_id": thread_id,
        "stream":    stream,
        "tools_declared": json.dumps(tools),
    })
    if err:
        return err

    run_id  = _run_id()
    asst_id = _asst_id()
    now     = _ts()

    # Pick one function tool for the requires_action exposure.
    import random as _rnd
    fn = _rnd.choice(_FAKE_FUNCTIONS)
    call_id = f"call_{uuid.uuid4().hex[:20]}"
    tool_calls_pending = [{
        "id":       call_id,
        "type":     "function",
        "function": {
            "name":      fn["name"],
            "arguments": json.dumps({"query": "latest data"} if fn["name"] == "search_knowledge_base"
                                    else {"action": "status_check", "payload": {}}),
        },
    }]

    _run_states[run_id] = {
        "thread_id":            thread_id,
        "status":               "queued",
        "poll_count":           0,
        "tool_calls_pending":   tool_calls_pending,
        "tool_outputs_submitted": [],
        "created_at":           now,
        "model":                model,
        "asst_id":              asst_id,
    }

    run_obj = _build_run_obj(run_id, thread_id, _run_states[run_id])

    if not stream:
        return JSONResponse(run_obj)

    # Streaming: SSE event sequence
    async def _sse_stream():
        state = _run_states[run_id]

        def _evt(event_name: str, obj: dict) -> str:
            return f"event: {event_name}\ndata: {json.dumps(obj)}\n\n"

        # thread.run.created
        state["status"] = "queued"
        yield _evt("thread.run.created", _build_run_obj(run_id, thread_id, state))
        await asyncio.sleep(0.05)

        # thread.run.in_progress
        state["status"] = "in_progress"
        yield _evt("thread.run.in_progress", _build_run_obj(run_id, thread_id, state))
        await asyncio.sleep(0.05)

        # thread.run.requires_action
        state["status"] = "requires_action"
        yield _evt("thread.run.requires_action", _build_run_obj(run_id, thread_id, state))
        await asyncio.sleep(0.05)

        yield "event: done\ndata: [DONE]\n\n"

    return StreamingResponse(
        _sse_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/v1/threads/{thread_id}/runs/{run_id}")
async def get_run(thread_id: str, run_id: str, request: Request):
    auth, err = await _require_auth(request)

    state = _run_states.get(run_id)
    if state is None:
        # Seed a plausible state for runs we don't have in memory
        state = {
            "thread_id": thread_id, "status": "completed",
            "poll_count": 2, "tool_calls_pending": [],
            "tool_outputs_submitted": [], "created_at": _ts() - 3,
            "model": "gpt-4o", "asst_id": _asst_id(),
        }

    # Advance state machine on each poll
    poll = state["poll_count"]
    if poll == 0:
        state["status"] = "in_progress"
    elif poll == 1:
        state["status"] = "requires_action"
    elif poll >= 2 and state["status"] == "requires_action":
        # Stay in requires_action until tool outputs are submitted
        pass
    state["poll_count"] = poll + 1

    await _log(request, 200 if not err else 401, auth, None, {
        "operation":   "poll_run",
        "thread_id":   thread_id,
        "run_id":      run_id,
        "run_status":  state["status"],
        "poll_count":  poll,
    })
    if err:
        return err

    return JSONResponse(_build_run_obj(run_id, thread_id, state))


@router.post("/v1/threads/{thread_id}/runs/{run_id}/submit_tool_outputs")
async def submit_tool_outputs(thread_id: str, run_id: str, request: Request):
    """
    PRIMARY capture endpoint for agentic sessions.
    Tool outputs reveal what the agent actually computed - the highest-value
    signal in the Assistants API surface. Log verbatim, never evaluate.
    """
    auth, err = await _require_auth(request)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    tool_outputs = data.get("tool_outputs", [])

    await _log(request, 200 if not err else 401, auth, None, {
        "operation":     "submit_tool_outputs",
        "thread_id":     thread_id,
        "run_id":        run_id,
        "tool_outputs":  json.dumps(tool_outputs)[:5000],
        "output_count":  len(tool_outputs),
    })
    if err:
        return err

    # Advance state → completed
    state = _run_states.get(run_id)
    if state is not None:
        state["status"] = "completed"
        state["tool_outputs_submitted"] = tool_outputs
    else:
        state = {
            "thread_id": thread_id, "status": "completed",
            "poll_count": 3, "tool_calls_pending": [],
            "tool_outputs_submitted": tool_outputs,
            "created_at": _ts() - 5, "model": "gpt-4o", "asst_id": _asst_id(),
        }

    return JSONResponse(_build_run_obj(run_id, thread_id, state))


@router.get("/v1/threads/{thread_id}/runs/{run_id}/steps")
async def list_run_steps(thread_id: str, run_id: str, request: Request):
    """
    Run steps - used by LangChain, AutoGen, and other frameworks to track
    intermediate tool call progress. Serves as an additional engagement hook.
    """
    auth, err = await _require_auth(request)
    await _log(request, 200 if not err else 401, auth, None, {
        "operation": "list_run_steps",
        "thread_id": thread_id,
        "run_id":    run_id,
    })
    if err:
        return err

    state = _run_states.get(run_id, {})
    tool_calls = state.get("tool_calls_pending", [])
    now = _ts()
    steps = []
    if tool_calls:
        steps.append({
            "id":           f"step_{uuid.uuid4().hex[:24]}",
            "object":       "thread.run.step",
            "created_at":   now - 2,
            "run_id":       run_id,
            "assistant_id": state.get("asst_id", _asst_id()),
            "thread_id":    thread_id,
            "type":         "tool_calls",
            "status":       state.get("status", "in_progress"),
            "step_details": {
                "type":       "tool_calls",
                "tool_calls": tool_calls,
            },
            "last_error": None,
            "expired_at": None,
            "cancelled_at": None,
            "failed_at": None,
            "completed_at": now if state.get("status") == "completed" else None,
            "metadata": {},
            "usage": None,
        })

    return JSONResponse({
        "object":   "list",
        "data":     steps,
        "first_id": steps[0]["id"] if steps else None,
        "last_id":  steps[-1]["id"] if steps else None,
        "has_more": False,
    })


@router.get("/v1/threads/{thread_id}/messages")
async def list_messages(thread_id: str, request: Request):
    """
    Return thread messages including a fake assistant reply.
    The reply embeds the canary token issued at thread creation.
    """
    auth, err = await _require_auth(request)
    await _log(request, 200 if not err else 401, auth, None, {
        "operation": "list_messages",
        "thread_id": thread_id,
    })
    if err:
        return err

    thread = await _get_thread(thread_id)
    canary_token = thread.get("canary_issued") if thread else None

    # Build fake assistant reply with embedded canary.
    reply_content = sample_chat_content(canary_token=canary_token or "")
    messages = []
    if thread:
        try:
            messages = json.loads(thread.get("messages_json") or "[]")
        except Exception:
            messages = []

    now = _ts()
    data = [
        {
            "id": _msg_id(),
            "object": "thread.message",
            "created_at": now,
            "thread_id": thread_id,
            "role": "assistant",
            "content": [{"type": "text", "text": {"value": reply_content, "annotations": []}}],
            "status": "completed",
            "metadata": {},
        }
    ] + [
        {
            "id": m.get("id", _msg_id()),
            "object": "thread.message",
            "created_at": now - 3,
            "thread_id": thread_id,
            "role": m.get("role", "user"),
            "content": [{"type": "text", "text": {"value": m.get("content", ""), "annotations": []}}],
            "status": "completed",
            "metadata": {},
        }
        for m in messages
    ]

    return JSONResponse({
        "object": "list",
        "data": data,
        "first_id": data[0]["id"] if data else None,
        "last_id": data[-1]["id"] if data else None,
        "has_more": False,
    })


@router.get("/v1/threads/{thread_id}")
async def get_thread(thread_id: str, request: Request):
    auth, err = await _require_auth(request)
    await _log(request, 200 if not err else 401, auth, None, {
        "operation": "get_thread", "thread_id": thread_id,
    })
    if err:
        return err
    return JSONResponse({
        "id": thread_id, "object": "thread",
        "created_at": _ts(), "metadata": {}, "tool_resources": {},
    })


@router.get("/v1/assistants")
async def list_assistants(request: Request):
    auth, err = await _require_auth(request)
    await _log(request, 200 if not err else 401, auth, None, {
        "operation": "list_assistants",
    })
    if err:
        return err
    return JSONResponse({"object": "list", "data": [], "first_id": None, "last_id": None, "has_more": False})
