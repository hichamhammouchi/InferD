"""
Canary token system for InferD.

Purpose:
    Detect LLM-mediated sessions - i.e. sessions where an AI agent is
    processing our honeypot responses and including the processed content
    in subsequent requests.

Design:
    Canary-capable response paths issue a unique token per HTTP session (and
    Assistants/MCP retain it in their own state) before returning a response:

        INFERD-{base32(session_id_bytes[:5]).upper().rstrip('=')}

    This token is embedded in fake assistant responses as a plausible
    system annotation that an LLM agent is likely to include in its
    context and echo back:

        [Context: session_token=INFERD-MFRA3]

    When any subsequent request arrives containing a known canary string,
    we record:
        - Which session issued the canary
        - When it was echoed
        - Which event (request) contained the echo
        - Whether the echo came from the same or a different IP session
          (cross-IP echo = strong evidence of agent-mediated processing)

    The canary registry is kept in-memory (dict) for fast O(1) lookup and is
    synchronously persisted to SQLite before it can appear in a response.

Scientific note:
    A static canary (same string for all sessions) would only give a
    binary signal. Per-session canaries give session attribution: you
    know exactly which response the agent was processing when it echoed
    the token back. This enables reconstruction of the full
    attacker→honeypot→agent→honeypot loop.
"""

import base64
import re
import uuid
from typing import NamedTuple

from honeypot.core.config import settings

# Registry

class CanaryRecord(NamedTuple):
    token: str
    session_id: str
    service: str          # 'assistants' | 'mcp'
    issued_at_us: int


# token string → CanaryRecord (in-memory fast lookup)
_registry: dict[str, CanaryRecord] = {}

# Pre-compiled regex for fast scan of request bodies.
# Matches INFERD- followed by 6-10 uppercase base32 chars.
_CANARY_RE = re.compile(r"INFERD-([A-Z2-7]{6,10})")


# Issue

def issue(session_id: str, service: str, timestamp_us: int) -> str:
    """
    Generate and register a canary token for a session.
    Returns the token string to embed in the response.
    """
    import random
    if random.random() > settings.canary_injection_rate:
        return ""   # No canary for this response.

    # Derive token from session_id bytes for determinism per session.
    sid_bytes = uuid.UUID(session_id).bytes[:5]
    suffix = base64.b32encode(sid_bytes).decode().rstrip("=").upper()
    token = f"INFERD-{suffix}"

    record = CanaryRecord(
        token=token,
        session_id=session_id,
        service=service,
        issued_at_us=timestamp_us,
    )
    _registry[token] = record
    return token


def embed(token: str, response_text: str) -> str:
    """
    Embed the canary token into a response text.
    Placed at the end as a plausible system annotation.
    An LLM agent processing this response will include it in its
    context window and may echo it in a subsequent request.
    """
    if not token:
        return response_text
    annotation = f"\n\n[Context: session_token={token}]"
    return response_text + annotation


# Detect

def scan(payload: str | bytes) -> str | None:
    """
    Scan an inbound request payload for any known canary token.
    Returns the matched token string, or None if no match.

    Call this on the raw request body before any parsing - we want to
    catch canaries even in malformed or unexpected payload structures.
    """
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8", errors="replace")
        except Exception:
            return None

    matches = _CANARY_RE.findall(payload)
    for suffix in matches:
        candidate = f"INFERD-{suffix}"
        if candidate in _registry:
            return candidate
    return None


def lookup(token: str) -> CanaryRecord | None:
    """Return the CanaryRecord for a token, or None if not registered."""
    return _registry.get(token)


async def issue_and_persist(session_id: str, service: str, timestamp_us: int) -> str:
    """Issue a token and persist it before returning it in a response."""
    token = issue(session_id, service, timestamp_us)
    if token:
        from honeypot.core import database
        # Persistence must complete before the token is sent: another worker
        # must be able to recognize an immediate echoed response.
        await database.write_rows([{"table": "canary_tokens", "row": {
            "token": token,
            "session_id": session_id,
            "service": service,
            "issued_at_us": timestamp_us,
        }}])
    return token


async def lookup_persisted(token: str) -> CanaryRecord | None:
    """Resolve a canary from memory or SQLite, supporting another worker."""
    record = lookup(token)
    if record:
        return record
    from honeypot.core.database import get_connection
    conn = await get_connection()
    async with conn.execute(
        "SELECT token, session_id, service, issued_at_us FROM canary_tokens WHERE token = ?",
        (token,),
    ) as cursor:
        row = await cursor.fetchone()
    if row is None:
        return None
    record = CanaryRecord(*row)
    _registry[token] = record
    return record


async def scan_persisted(payload: str | bytes) -> str | None:
    """Find an issued canary, including tokens created by another process."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    for suffix in _CANARY_RE.findall(payload):
        token = f"INFERD-{suffix}"
        if await lookup_persisted(token):
            return token
    return None
