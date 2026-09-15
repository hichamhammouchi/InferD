"""
Shared request middleware and app factory.

create_app() wires InferDMiddleware (source IP, rate limit, canary scan,
session tracking) and the DB lifespan into each service. Handlers read
request.state: source_ip, geo, start_us, raw_body, canary_echo, session_id.
Sessions are kept in memory, keyed by source IP, and expire after 30 min idle.
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from honeypot.core import anomaly, canary, database, geoip, ip, logger, ratelimit
from honeypot.core.logger import EventRecord
from honeypot.core.config import settings

# In-memory session cache
_sessions: dict[str, dict[str, Any]] = {}

SESSION_TIMEOUT_US = 30 * 60 * 1000000   # 30 minutes in microseconds


def _get_or_create_session(source_ip: str, now_us: int) -> tuple[str, bool]:
    """
    Return (session_id, is_new).
    Creates a new session if none exists or last seen > 30 min ago.
    """
    entry = _sessions.get(source_ip)
    if entry and (now_us - entry["last_seen_us"]) < SESSION_TIMEOUT_US:
        entry["last_seen_us"] = now_us
        return entry["session_id"], False
    # New or expired session.
    session_id = str(uuid.uuid4())
    _sessions[source_ip] = {
        "session_id": session_id,
        "last_seen_us": now_us,
        "first_seen_us": now_us,
        "endpoint_sequence": [],
        "request_count": 0,
    }
    return session_id, True


# Middleware

class InferDMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, service_name: str) -> None:
        super().__init__(app)
        self.service_name = service_name

    async def dispatch(self, request: Request, call_next) -> Response:
        now_us = logger.now_us()

        # IP extraction and enrichment
        source_ip = ip.extract_real_ip(request)
        geo = geoip.enrich(source_ip)

        request.state.source_ip = source_ip
        request.state.geo = geo
        request.state.start_us = now_us
        request.state.service = self.service_name

        # Read the request body with the same 32 MiB bound used by the TLS proxy.
        body = bytearray()
        too_large = False
        try:
            async for chunk in request.stream():
                if len(body) + len(chunk) > settings.max_request_body_bytes:
                    too_large = True
                    break
                body.extend(chunk)
        except Exception:
            body = bytearray()
        request._body = bytes(body)
        request.state.raw_body = request._body
        request.state.canary_echo = await canary.scan_persisted(request.state.raw_body)

        # Anomaly detection
        try:
            import json as _json
            _parsed = _json.loads(request.state.raw_body) if request.state.raw_body else None
        except Exception:
            _parsed = None
        request.state.anomaly_flags = anomaly.scan(
            body=request.state.raw_body,
            parsed=_parsed,
            headers=dict(request.headers),
            endpoint=f"{request.method} {request.url.path}",
        )

        # Session management
        session_id, is_new = _get_or_create_session(source_ip, now_us)
        request.state.session_id = session_id

        # Update in-memory session state.
        sess = _sessions[source_ip]
        sess["request_count"] = sess.get("request_count", 0) + 1
        endpoint_key = f"{request.method} {request.url.path}"
        sess["endpoint_sequence"].append(endpoint_key)

        # Upsert session row to SQLite (async, non-blocking).
        session_row: dict[str, Any] = {
            "session_id":        session_id,
            "source_ip":         source_ip,
            "asn":               geo.asn,
            "asn_org":           geo.asn_org,
            "country_code":      geo.country_code,
            "first_seen_us":     sess["first_seen_us"],
            "last_seen_us":      now_us,
            "service":           self.service_name,
            "request_count":     sess["request_count"],
            "user_agent":        request.headers.get("user-agent", ""),
            "tls_cipher":        request.headers.get("x-tls-cipher"),
            "tls_protocol":      request.headers.get("x-tls-protocol"),
            "http_version":      request.scope.get("http_version", ""),
            "endpoint_sequence": json.dumps(sess["endpoint_sequence"][-50:]),  # last 50
        }
        # Canary echo: update SQLite records
        if request.state.canary_echo:
            token = request.state.canary_echo
            record = await canary.lookup_persisted(token)
            if record:
                # Mark this session as canary-confirmed (agent in the loop).
                sess["canary_confirmed"] = True
                session_row["canary_confirmed"] = 1

        await logger.upsert_session(session_row)

        if too_large:
            await self._log_unhandled(request, 413)
            return JSONResponse({"detail": "Request body too large"}, status_code=413)

        # Rate limits must also be observable events. Run this after assigning
        # request state so a rejected request has the same attribution fields.
        allowed, _ = await ratelimit.check(source_ip)
        if not allowed:
            await self._log_unhandled(request, 429)
            return JSONResponse(ratelimit.rate_limit_response(), status_code=429)

        response = await call_next(request)
        # Route handlers log their successful/expected responses. Framework
        # 404s have no handler, so log them here without duplicating events.
        if response.status_code == 404 and request.scope.get("endpoint") is None:
            await self._log_unhandled(request, 404)
        return response

    async def _log_unhandled(self, request: Request, status: int) -> None:
        """Record middleware-generated responses such as 404 and 429."""
        body = getattr(request.state, "raw_body", b"")
        try:
            payload = body.decode("utf-8", errors="replace") if body else None
        except Exception:
            payload = None
        await logger.log_event(EventRecord(
            event_id=str(uuid.uuid4()),
            session_id=request.state.session_id,
            timestamp_us=request.state.start_us,
            source_ip=request.state.source_ip,
            asn=request.state.geo.asn,
            asn_org=request.state.geo.asn_org,
            country_code=request.state.geo.country_code,
            service=self.service_name,
            endpoint=f"{request.method} {request.url.path}",
            http_method=request.method,
            http_version=request.scope.get("http_version", ""),
            user_agent=request.headers.get("user-agent", ""),
            tls_cipher=request.headers.get("x-tls-cipher"),
            tls_protocol=request.headers.get("x-tls-protocol"),
            request_size_bytes=len(body),
            auth_key_prefix=None,
            auth_key_hash=None,
            is_honeytoken=False,
            honeytoken_id=None,
            payload_json=payload,
            model_requested=None,
            response_status=status,
            response_time_ms=(logger.now_us() - request.state.start_us) / 1000,
            canary_echo_detected=bool(request.state.canary_echo),
            canary_token=request.state.canary_echo,
            canary_source_session=(canary.lookup(request.state.canary_echo).session_id
                                   if request.state.canary_echo and canary.lookup(request.state.canary_echo)
                                   else None),
            anomaly_flags=getattr(request.state, "anomaly_flags", None),
        ))


# Lifespan

@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup: init DB and start batch writer. Shutdown: flush and close."""
    await database.init_db()
    writer_task = asyncio.create_task(database.batch_writer())
    try:
        yield
    finally:
        writer_task.cancel()
        try:
            await writer_task
        except asyncio.CancelledError:
            pass
        await database.close()


# App factory

def create_app(service_name: str) -> FastAPI:
    """
    Create a FastAPI application for a honeypot service.
    Call this in each services/*.py module:

        app = create_app("ollama")
        app.include_router(ollama.router)
    """
    app = FastAPI(
        title=f"InferD [{service_name}]",
        docs_url=None,    # No /docs - reduces fingerprinting surface.
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )
    app.add_middleware(InferDMiddleware, service_name=service_name)
    return app
