"""
Event logging. Every request becomes one EventRecord, written synchronously to a
daily JSONL file (the canonical record) and enqueued for SQLite (a structured
index that can be rebuilt from the JSONL).
"""

import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from honeypot.core import database
from honeypot.core.config import settings


# Event schema

@dataclass
class EventRecord:
    # Identity
    event_id: str
    session_id: str
    timestamp_us: int

    # Network
    source_ip: str
    asn: int | None
    asn_org: str | None
    country_code: str | None

    # HTTP
    service: str
    endpoint: str           # "POST /v1/chat/completions"
    http_method: str
    http_version: str
    user_agent: str
    tls_cipher: str | None
    tls_protocol: str | None
    request_size_bytes: int

    # Auth
    auth_key_prefix: str | None        # first 7 chars
    auth_key_hash: str | None          # SHA-256 hex of full token
    is_honeytoken: bool
    honeytoken_id: str | None

    # Payload (full, never truncated)
    payload_json: str | None           # raw request body as JSON string

    # Service-specific extras (arbitrary dict, serialised into payload_json
    # or stored as top-level fields for common high-value fields)
    model_requested: str | None

    # Response
    response_status: int
    response_time_ms: float

    # Canary
    canary_echo_detected: bool
    canary_token: str | None
    canary_source_session: str | None

    # Anomaly flags (comma-separated structural anomaly signals)
    anomaly_flags: str | None = None

    # Optional extras (service-specific structured fields)
    extras: dict[str, Any] = field(default_factory=dict)

    # Raw presented key. Persisted only when STORE_RAW_AUTH_KEYS is enabled.
    auth_key_raw: str | None = None


# JSONL writer

def _jsonl_path() -> Path:
    """Return today's JSONL file path, creating the directory if needed."""
    date_str = time.strftime("%Y-%m-%d", time.gmtime())
    path = settings.raw_log_dir / f"{date_str}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _append_jsonl(record: dict[str, Any]) -> None:
    """
    Append one JSON line while holding a Linux advisory file lock.
    Request bodies can be up to 32 MB, so the former PIPE_BUF atomic-write
    assumption was invalid. Every InferD process uses this lock; a crash can
    still lose an in-flight write and is intentionally not claimed otherwise.
    """
    try:
        import fcntl
        line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8")
        fd = os.open(_jsonl_path(), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            view = memoryview(line)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short JSONL write")
                view = view[written:]
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    except Exception as exc:
        print(f"[logger] JSONL write failed: {exc}", file=sys.stderr)


# Public API

async def log_event(ev: EventRecord) -> None:
    """
    Log an event to JSONL (synchronous) and enqueue for SQLite (async).
    Call this at the end of every request handler.
    """
    rec = asdict(ev)
    if not settings.store_raw_auth_keys:
        rec["auth_key_raw"] = None

    # Flatten extras into the top-level dict for JSONL readability.
    extras = rec.pop("extras", {})
    rec.update(extras)

    # 1. JSONL - always, synchronously, before anything else.
    _append_jsonl(rec)

    # 2. SQLite - async, via batch writer queue.
    # Store all standard fields; extras stored in payload_json.
    db_row = {
        "event_id":              ev.event_id,
        "session_id":            ev.session_id,
        "timestamp_us":          ev.timestamp_us,
        "source_ip":             ev.source_ip,
        "asn":                   ev.asn,
        "asn_org":               ev.asn_org,
        "country_code":          ev.country_code,
        "service":               ev.service,
        "endpoint":              ev.endpoint,
        "http_method":           ev.http_method,
        "http_version":          ev.http_version,
        "user_agent":            ev.user_agent,
        "tls_cipher":            ev.tls_cipher,
        "tls_protocol":          ev.tls_protocol,
        "request_size_bytes":    ev.request_size_bytes,
        "auth_key_prefix":       ev.auth_key_prefix,
        "auth_key_hash":         ev.auth_key_hash,
        "auth_key_raw":          ev.auth_key_raw if settings.store_raw_auth_keys else None,
        "is_honeytoken":         int(ev.is_honeytoken),
        "honeytoken_id":         ev.honeytoken_id,
        "model_requested":       ev.model_requested,
        "payload_json":          ev.payload_json,
        "response_status":       ev.response_status,
        "response_time_ms":      ev.response_time_ms,
        "canary_echo_detected":  int(ev.canary_echo_detected),
        "canary_token":          ev.canary_token,
        "canary_source_session": ev.canary_source_session,
        "anomaly_flags":         ev.anomaly_flags or None,
    }
    await database.enqueue("events", db_row)
    if ev.canary_echo_detected and ev.canary_token:
        # The event ID is created by the handler, so link the canary only here
        # after the complete EventRecord exists.
        await database.execute(
            "UPDATE canary_tokens SET echo_detected_at_us = COALESCE(echo_detected_at_us, ?), "
            "echo_event_id = COALESCE(echo_event_id, ?), "
            "echo_session_id = COALESCE(echo_session_id, ?) WHERE token = ?",
            (ev.timestamp_us, ev.event_id, ev.session_id, ev.canary_token),
        )


async def upsert_session(session_row: dict[str, Any]) -> None:
    """Upsert a session record into SQLite."""
    await database.enqueue("sessions", session_row)


def now_us() -> int:
    """Current time in microseconds since Unix epoch."""
    return int(time.time() * 1000000)
