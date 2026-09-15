"""
OpenClaw-shaped AI agent gateway emulator for InferD.

Port 18789 exposes a control UI, REST management routes, and a WebSocket
agent channel. The emulator records authentication attempts, skill-package
references, owner-context fields, administrative probes, and raw WebSocket
frames without executing commands or fetching attacker-supplied URLs.

Telemetry labels describe observed probe structure. They do not assert that a
generic route is an exact reproduction of a particular upstream vulnerability.
"""

import json
import time
import uuid

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from honeypot.core import canary as canary_mod
from honeypot.core import logger, ratelimit
from honeypot.core.config import settings
from honeypot.core.logger import EventRecord, now_us

router = APIRouter()

_OPENCLAW_VERSION  = "2026.4.21"
_GATEWAY_BUILD     = "a9c4d2f"

# Issued login tokens - used to detect reuse across requests
_ACTIVE_TOKENS: set[str] = set()

# WebSocket session state: session_id → {"authed": bool, "token": str|None}
_ws_sessions: dict[str, dict] = {}

# Fake installed skills list
_FAKE_SKILLS = [
    {
        "id":          "web-search-pro",
        "name":        "Web Search Pro",
        "version":     "1.3.2",
        "author":      "ClawHub Official",
        "description": "Search the web and return structured results",
        "installed":   True,
        "trusted":     True,
    },
    {
        "id":          "calendar-sync",
        "name":        "Calendar Sync",
        "version":     "2.0.1",
        "author":      "ClawHub Official",
        "description": "Sync events across Google Calendar, Outlook, and Apple Calendar",
        "installed":   True,
        "trusted":     True,
    },
    {
        "id":          "file-manager",
        "name":        "File Manager",
        "version":     "1.1.0",
        "author":      "community-dev",
        "description": "Read and write files from local filesystem",
        "installed":   True,
        "trusted":     False,
    },
]


# Logging helper

async def _log_http(
    request: Request,
    status: int,
    extras: dict,
) -> None:
    body = request.state.raw_body
    try:
        payload_obj = json.loads(body) if body else {}
    except Exception:
        payload_obj = {"_raw": body.decode("utf-8", errors="replace")} if body else {}

    # Record attempts to present a localhost-looking origin on a direct service.
    origin    = request.headers.get("origin", "")
    forwarded = request.headers.get("x-forwarded-for", "")
    referer   = request.headers.get("referer", "")
    localhost_spoof = any(
        marker in h
        for h in [origin, forwarded, referer]
        for marker in ["127.0.0.1", "localhost", "::1"]
    )
    if localhost_spoof:
        extras["localhost_trust_probe"] = True
        extras["localhost_origin_header"] = origin or forwarded or referer

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="openclaw",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=None,
        tls_protocol=None,
        request_size_bytes=len(body) if body else 0,
        auth_key_prefix=None,
        auth_key_hash=None,
        auth_key_raw=None,
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


async def _log_ws_frame(
    websocket: WebSocket,
    source_ip: str,
    session_id: str,
    frame_data: str | bytes,
    frame_seq: int,
    geo,
) -> None:
    """Log a single WebSocket frame as an event."""
    now = now_us()

    # Parse frame if JSON
    try:
        if isinstance(frame_data, bytes):
            frame_str = frame_data.decode("utf-8", errors="replace")
        else:
            frame_str = frame_data
        frame_obj = json.loads(frame_str)
    except (json.JSONDecodeError, Exception):
        frame_str = repr(frame_data)[:2000]
        frame_obj = {"_raw": frame_str}

    # Extract high-value owner-context and command fields.
    extras = {
        "ws_frame_seq":  frame_seq,
        "ws_frame_type": frame_obj.get("type", "") if isinstance(frame_obj, dict) else "unknown",
        "ws_frame_size": len(frame_data) if frame_data else 0,
    }

    if isinstance(frame_obj, dict) and frame_obj.get("senderIsOwner") is True:
        extras["owner_context_probe"] = True
        extras["sender_is_owner"]      = True
        extras["execute_command"]      = str(frame_obj.get("command", ""))[:500]
        extras["execute_args"]         = json.dumps(frame_obj.get("args", []))[:500]

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=session_id,
        timestamp_us=now,
        source_ip=source_ip,
        asn=geo.asn if geo else None,
        asn_org=geo.asn_org if geo else None,
        country_code=geo.country_code if geo else None,
        service="openclaw",
        endpoint="WS /ws",
        http_method="WS",
        http_version="websocket",
        user_agent="",
        tls_cipher=None,
        tls_protocol=None,
        request_size_bytes=len(frame_data) if frame_data else 0,
        auth_key_prefix=None,
        auth_key_hash=None,
        auth_key_raw=None,
        is_honeytoken=False,
        honeytoken_id=None,
        payload_json=json.dumps(frame_obj, ensure_ascii=False),
        model_requested=None,
        response_status=200,
        response_time_ms=0,
        canary_echo_detected=False,
        canary_token=None,
        canary_source_session=None,
        extras=extras,
    )
    await logger.log_event(ev)


# HTTP Routes

@router.get("/")
async def root(request: Request):
    await _log_http(request, 302, {"operation": "root"})
    from starlette.responses import RedirectResponse
    return RedirectResponse(url="/openclaw")


@router.get("/openclaw")
async def control_ui(request: Request):
    """Control UI - the HTTP face of port 18789."""
    await _log_http(request, 200, {"operation": "control_ui"})
    host = request.headers.get("host", "localhost:18789")
    scheme = "wss" if request.url.scheme == "https" else "ws"
    http_scheme = request.url.scheme or "http"
    html = """<!DOCTYPE html>
<html><head><title>OpenClaw Gateway</title>
<style>body{{font-family:sans-serif;max-width:800px;margin:40px auto;padding:20px}}
.status{{color:#2d7a2d;font-weight:bold}}</style></head>
<body>
<h1>OpenClaw Gateway <span style="font-size:0.6em;color:#888">v{ver}</span></h1>
<p>Status: <span class="status">● Running</span></p>
<p>Connected agents: <strong>1</strong></p>
<p>Installed skills: <strong>{skills}</strong></p>
<hr>
<h3>Gateway Configuration</h3>
<ul>
<li>WebSocket endpoint: <code>{ws_scheme}://{host}/ws</code></li>
<li>API endpoint: <code>{http_scheme}://{host}/api</code></li>
<li>Auth: <code>password</code> (set in config.yaml)</li>
</ul>
<p><a href="/api/gateway/status">Gateway Status</a> |
<a href="/api/skills/list">Installed Skills</a></p>
</body></html>""".format(
        ver=_OPENCLAW_VERSION, skills=len(_FAKE_SKILLS),
        host=host, ws_scheme=scheme, http_scheme=http_scheme,
    )
    return HTMLResponse(html)


@router.get("/api/gateway/status")
async def gateway_status(request: Request):
    await _log_http(request, 200, {"operation": "gateway_status"})
    return JSONResponse({
        "status":             "running",
        "version":            _OPENCLAW_VERSION,
        "build":              _GATEWAY_BUILD,
        "uptime_seconds":     int(time.time()) % 86400,
        "connected_agents":   1,
        "skills_loaded":      len(_FAKE_SKILLS),
        "auth_enabled":       True,
        "localhost_trusted":  True,
        "senderIsOwner_check": False,
    })


@router.post("/api/auth/login")
async def auth_login(request: Request):
    """
    Password authentication surface.
    Logs every password attempt verbatim. This builds a brute-force corpus.
    Always returns success to keep the attacker engaged.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    password_attempt = data.get("password", "") or data.get("pass", "") or data.get("token", "")

    await _log_http(request, 200, {
        "operation":        "auth_login",
        "password_attempt": str(password_attempt)[:200],  # full attempt logged
        "username":         str(data.get("username", "admin"))[:100],
    })

    # Always return a token to keep the interaction stateful.
    fake_token = f"oc_gw_{uuid.uuid4().hex[:32]}"
    _ACTIVE_TOKENS.add(fake_token)
    return JSONResponse({
        "success": True,
        "token":   fake_token,
        "expires": int(time.time()) + 86400,
        "role":    "admin",
    })


@router.get("/api/skills/list")
async def skills_list(request: Request):
    await _log_http(request, 200, {"operation": "skills_list"})
    return JSONResponse({"skills": _FAKE_SKILLS})


@router.post("/api/skills/install")
async def skills_install(request: Request):
    """
    Skill installation endpoint. Package URLs are logged verbatim but never fetched.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    package_url = (
        data.get("package_url") or data.get("url") or
        data.get("source") or data.get("registry_url") or ""
    )
    skill_name = data.get("name") or data.get("skill_id") or "unknown"

    await _log_http(request, 200, {
        "operation":          "skill_install",
        "skill_package_url":  str(package_url)[:1000],  # logged, never fetched
        "skill_name":         str(skill_name)[:200],
        "sandbox_bypass":     bool(data.get("skip_sandbox") or data.get("no_sandbox")),
        "path_env_inject":    str(data.get("env", {}).get("PATH", ""))[:200],
    })

    return JSONResponse({
        "success":    True,
        "skill_id":   str(skill_name).lower().replace(" ", "-"),
        "installed":  True,
        "version":    data.get("version", "latest"),
        "message":    "Skill installed successfully",
    })


@router.post("/api/execute")
async def execute(request: Request):
    """
    Agent execution-shaped endpoint. Owner-context and command fields are logged
    verbatim and never executed.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    sender_is_owner = data.get("senderIsOwner", False)
    command         = data.get("command") or data.get("action") or ""
    args            = data.get("args") or data.get("arguments") or []

    extras = {
        "operation":       "execute",
        "sender_is_owner": sender_is_owner,
        "command_field":   str(command)[:500],
        "args_field":      json.dumps(args)[:500],
    }
    if sender_is_owner is True:
        extras["owner_context_probe"] = True

    await _log_http(request, 200, extras)

    return JSONResponse({
        "success": True,
        "result":  {"output": "Command executed", "exit_code": 0},
        "task_id": str(uuid.uuid4()),
    })


@router.post("/api/agent/register")
async def agent_register(request: Request):
    """Agent registration - log capabilities and connection metadata."""
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    await _log_http(request, 200, {
        "operation":          "agent_register",
        "agent_id":           str(data.get("agent_id", ""))[:100],
        "agent_capabilities": json.dumps(data.get("capabilities", []))[:500],
        "platform":           str(data.get("platform", ""))[:100],
        "agent_version":      str(data.get("version", ""))[:50],
    })

    return JSONResponse({
        "registered":   True,
        "agent_id":     data.get("agent_id") or str(uuid.uuid4()),
        "gateway_token": f"oc_agent_{uuid.uuid4().hex[:24]}",
    })


@router.get("/api/admin/users")
async def admin_users(request: Request):
    """
    Administrative lure endpoint. Access is recorded whether or not an
    Authorization header is present.
    """
    auth_header = request.headers.get("authorization", "")
    await _log_http(request, 200, {
        "operation":        "admin_users",
        "had_auth_header":  bool(auth_header),
        "admin_access_probe": True,
    })
    return JSONResponse({
        "users": [
            {"id": "1", "username": "admin", "role": "owner", "active": True},
            {"id": "2", "username": "agent-service", "role": "agent", "active": True},
        ]
    })


@router.get("/api/config")
async def config_endpoint(request: Request):
    """
    Configuration-shaped lure exposing the gateway trust posture.
    """
    await _log_http(request, 200, {"operation": "config"})
    return JSONResponse({
        "gateway": {
            "port":             18789,
            "version":          _OPENCLAW_VERSION,
            "trust_localhost":  True,
            "auth_required":    True,
            "rate_limit":       "shared_ip_bucket"
        },
        "skills": {
            "sandbox_enabled": True,
            "allow_path_env":  True,    # PATH injection vector
        },
        "mcp": {
            "enabled":          True,
            "sender_is_owner_check": False,
        }
    })


@router.get("/api/logs")
async def api_logs(request: Request):
    """
    Administrative log lure used to capture post-authentication probing.
    Probers that reach here after bypassing auth reveal full-compromise intent.
    """
    auth_header = request.headers.get("authorization", "")
    token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
    used_known_token = token in _ACTIVE_TOKENS
    await _log_http(request, 200, {
        "operation":        "admin_logs",
        "had_auth_header":  bool(auth_header),
        "used_login_token": used_known_token,
        "admin_access_probe": True,
    })
    return JSONResponse({
        "logs": [
            {"ts": int(time.time()) - 3600, "level": "INFO",  "msg": "Gateway started"},
            {"ts": int(time.time()) - 1800, "level": "INFO",  "msg": "Agent connected: agent-1"},
            {"ts": int(time.time()) - 600,  "level": "WARN",  "msg": "Skill execution timeout: file-manager"},
            {"ts": int(time.time()) - 60,   "level": "INFO",  "msg": "Skill installed: web-search-pro v1.3.2"},
        ]
    })


@router.post("/api/platform/connect")
async def platform_connect(request: Request):
    """
    Platform webhook registration - captures attacker-controlled webhook_url
    (exfiltration infrastructure), mirroring /api/skills/install logic.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    webhook_url   = data.get("webhook_url") or data.get("callback_url") or data.get("url") or ""
    platform      = data.get("platform") or data.get("type") or ""
    redirect_uri  = data.get("redirect_uri") or ""

    auth_header = request.headers.get("authorization", "")
    token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
    used_known_token = token in _ACTIVE_TOKENS

    await _log_http(request, 200, {
        "operation":        "platform_connect",
        "webhook_url":      str(webhook_url)[:1000],
        "redirect_uri":     str(redirect_uri)[:1000],
        "platform":         str(platform)[:100],
        "used_login_token": used_known_token,
    })
    return JSONResponse({
        "connected":    True,
        "platform_id":  str(uuid.uuid4()),
        "platform":     platform or "custom",
        "webhook_url":  webhook_url,
        "status":       "active",
    })


@router.get("/api/messages/history")
async def messages_history(request: Request):
    """
    Message history endpoint - reveals whether the prober is interested in
    past conversation data (data exfiltration pattern).
    """
    auth_header = request.headers.get("authorization", "")
    token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
    used_known_token = token in _ACTIVE_TOKENS
    await _log_http(request, 200, {
        "operation":        "messages_history",
        "had_auth_header":  bool(auth_header),
        "used_login_token": used_known_token,
    })
    return JSONResponse({
        "messages": [
            {"id": "m1", "ts": int(time.time()) - 7200, "from": "user", "text": "Hello"},
            {"id": "m2", "ts": int(time.time()) - 7190, "from": "agent", "text": "Hi! How can I help?"},
            {"id": "m3", "ts": int(time.time()) - 3600, "from": "user", "text": "Run the deployment script"},
        ],
        "total": 3,
    })


@router.post("/api/skills/{skill_id}/execute")
async def skill_execute(skill_id: str, request: Request):
    """
    Per-skill execution-shaped endpoint.
    Logs command + args from skill invocation payload verbatim, never executes.
    """
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    command = data.get("command") or data.get("action") or data.get("input") or ""
    args    = data.get("args") or data.get("arguments") or data.get("params") or []
    sender_is_owner = data.get("senderIsOwner", False)

    auth_header = request.headers.get("authorization", "")
    token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
    used_known_token = token in _ACTIVE_TOKENS

    extras = {
        "operation":        "skill_execute",
        "skill_id":         str(skill_id)[:100],
        "command":          str(command)[:500],
        "args":             json.dumps(args)[:500],
        "used_login_token": used_known_token,
        "sender_is_owner":  sender_is_owner,
    }
    if sender_is_owner is True:
        extras["owner_context_probe"] = True

    await _log_http(request, 200, extras)
    return JSONResponse({
        "success":  True,
        "skill_id": skill_id,
        "task_id":  str(uuid.uuid4()),
        "result":   {"output": "Skill executed", "exit_code": 0},
    })


# WebSocket Handler

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    OpenClaw agent WebSocket protocol.
    Phase 1: log raw frames only.
    Phase 2 (future): maintain session state across frames.

    Each frame → one event row in SQLite.
    Connection drop → loop exits cleanly.
    """
    await websocket.accept()

    # Extract connection metadata from the upgrade request
    # Trust X-Real-IP only for a local Nginx peer, just as HTTP middleware does.
    from honeypot.core.ip import extract_real_ip
    source_ip = extract_real_ip(websocket)
    from honeypot.core.geoip import enrich
    geo         = enrich(source_ip)
    session_id  = str(uuid.uuid4())
    frame_seq   = 0

    # Initialise per-session auth state
    _ws_sessions[session_id] = {"authed": False, "token": None}

    # Send a plausible welcome frame
    await websocket.send_text(json.dumps({
        "type":    "gateway_hello",
        "version": _OPENCLAW_VERSION,
        "session": session_id,
        "auth":    "required",
    }))

    try:
        while True:
            # Receive text or binary frames
            try:
                msg = await websocket.receive()
            except WebSocketDisconnect:
                break

            frame_data = msg.get("text") or msg.get("bytes") or b""
            if not frame_data:
                continue
            if len(frame_data) > settings.max_request_body_bytes:
                await websocket.close(code=1009)
                break
            allowed, _ = await ratelimit.check(source_ip)
            if not allowed:
                await websocket.close(code=1013)
                break

            frame_seq += 1

            # Parse frame before logging so auth state is current
            try:
                frame_obj = json.loads(frame_data) if isinstance(frame_data, str) \
                            else json.loads(frame_data.decode("utf-8", errors="replace"))
            except Exception:
                frame_obj = {}

            frame_type = frame_obj.get("type", "") if isinstance(frame_obj, dict) else ""

            # Track auth state transitions
            sess_state = _ws_sessions.get(session_id, {})
            if frame_type == "auth":
                ws_token = frame_obj.get("token", "")
                is_known_token = ws_token in _ACTIVE_TOKENS
                sess_state["authed"] = True
                sess_state["token"]  = ws_token

            await _log_ws_frame(
                websocket=websocket,
                source_ip=source_ip,
                session_id=session_id,
                frame_data=frame_data,
                frame_seq=frame_seq,
                geo=geo,
            )

            # Respond appropriately to common frame types
            if frame_type == "auth":
                ws_token = frame_obj.get("token", "")
                is_known_token = ws_token in _ACTIVE_TOKENS
                await websocket.send_text(json.dumps({
                    "type":             "auth_result",
                    "success":          True,
                    "token":            f"oc_{uuid.uuid4().hex[:24]}",
                    "used_login_token": is_known_token,
                }))
            elif frame_type == "task":
                await websocket.send_text(json.dumps({
                    "type":    "task_ack",
                    "task_id": frame_obj.get("id") or str(uuid.uuid4()),
                    "status":  "accepted",
                }))
            elif frame_type == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            else:
                # Generic ack for unknown frame types
                await websocket.send_text(json.dumps({
                    "type":   "ack",
                    "seq":    frame_seq,
                    "status": "ok",
                }))

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _ws_sessions.pop(session_id, None)
        try:
            await websocket.close()
        except Exception:
            pass


@router.websocket("/agent")
async def websocket_agent(websocket: WebSocket):
    """Alternative WebSocket path used by newer OpenClaw clients."""
    # Delegate to the same handler logic
    await websocket_endpoint(websocket)
