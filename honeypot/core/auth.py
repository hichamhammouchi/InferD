"""
API key extraction and honeytoken matching for InferD.

Handles Authorization header parsing, key format detection,
SHA-256 hashing for safe storage, and honeytoken registry lookup.

Key formats recognised:
    OpenAI:     sk-[A-Za-z0-9]{48}   or  sk-proj-[A-Za-z0-9]{...}
    Anthropic:  sk-ant-api03-[...]
    HF:         hf_[A-Za-z0-9]{34}

Raw credentials are retained only in request memory by default. Persistent
telemetry stores the prefix and SHA-256 hash unless STORE_RAW_AUTH_KEYS is
explicitly enabled.
"""

import hashlib
import re
from dataclasses import dataclass

import aiosqlite

from honeypot.core.database import get_connection

# Key format patterns

_FORMATS: list[tuple[str, re.Pattern]] = [
    # OpenAI: sk-<suffix> or sk-proj-<suffix>
    ("openai",     re.compile(r"^sk-[A-Za-z0-9\-_]{20,}")),
    # Anthropic: sk-ant-api03-<suffix> or any sk-ant- variant
    ("anthropic",  re.compile(r"^sk-ant-[A-Za-z0-9\-_]{20,}")),
    # HuggingFace: hf_<suffix>
    ("hf",         re.compile(r"^hf_[A-Za-z0-9]{10,}")),
    # Google Gemini: AIza<35 base64url chars> (39 chars total)
    ("gemini",     re.compile(r"^AIza[A-Za-z0-9\-_]{35}")),
    # Mistral: no known stable prefix; 32+ alphanum chars that don't match above.
    # This is a best-effort heuristic - Mistral keys carry no structural marker.
    ("mistral",    re.compile(r"^[A-Za-z0-9]{32,64}$")),
]


def detect_format(key: str) -> str | None:
    """Return the key format label, or None if unrecognised."""
    for label, pattern in _FORMATS:
        if pattern.match(key):
            return label
    return None


def hash_key(key: str) -> str:
    """Return SHA-256 hex digest of the raw key."""
    return hashlib.sha256(key.encode()).hexdigest()


# Auth header parsing

@dataclass
class AuthResult:
    raw_key: str | None          # Raw request value; persistence policy is enforced by logger.py
    key_prefix: str | None       # First 7 chars
    key_hash: str | None         # SHA-256
    key_format: str | None       # 'openai' | 'anthropic' | 'hf' | None
    is_honeytoken: bool
    honeytoken_id: str | None
    valid_format: bool           # True if key matches a known format regex


_NO_AUTH = AuthResult(
    raw_key=None, key_prefix=None, key_hash=None,
    key_format=None, is_honeytoken=False, honeytoken_id=None,
    valid_format=False,
)


def parse_auth_header(authorization: str | None) -> AuthResult:
    """
    Parse the Authorization header value.
    Does NOT do the honeytoken DB lookup (that's async - use check_honeytoken).
    """
    if not authorization:
        return _NO_AUTH

    # Strip "Bearer " prefix (case-insensitive).
    key = authorization.strip()
    if key.lower().startswith("bearer "):
        key = key[7:].strip()

    if not key:
        return _NO_AUTH

    fmt = detect_format(key)
    return AuthResult(
        raw_key=key,
        key_prefix=key[:7],
        key_hash=hash_key(key),
        key_format=fmt,
        is_honeytoken=False,    # set by check_honeytoken()
        honeytoken_id=None,
        valid_format=fmt is not None,
    )


async def check_honeytoken(auth: AuthResult) -> AuthResult:
    """
    Lookup the key hash in the token_registry table.
    Returns a new AuthResult with is_honeytoken and honeytoken_id set.
    """
    if auth.key_hash is None:
        return auth

    try:
        conn: aiosqlite.Connection = await get_connection()
        async with conn.execute(
            "SELECT token_id, revoked_at_us FROM token_registry WHERE token_hash = ?",
            (auth.key_hash,),
        ) as cur:
            row = await cur.fetchone()

        if row is None:
            return auth

        token_id, revoked_at_us = row
        if revoked_at_us is not None:
            return auth

        from honeypot.core.logger import now_us
        from honeypot.core import database
        await database.execute(
            """UPDATE token_registry
               SET use_count = use_count + 1,
                   first_use_at_us = COALESCE(first_use_at_us, ?)
               WHERE token_id = ? AND revoked_at_us IS NULL""",
            (now_us(), token_id),
        )

        return AuthResult(
            raw_key=auth.raw_key,
            key_prefix=auth.key_prefix,
            key_hash=auth.key_hash,
            key_format=auth.key_format,
            is_honeytoken=True,
            honeytoken_id=token_id,
            valid_format=auth.valid_format,
        )
    except Exception:
        return auth   # DB error → treat as non-honeytoken, don't crash.


def anthropic_auth_error(invalid: bool = True) -> dict:
    """Plausible Anthropic 401 error body."""
    if not invalid:
        return {
            "type": "error",
            "error": {
                "type": "authentication_error",
                "message": "No API key provided.",
            },
        }
    return {
        "type": "error",
        "error": {
            "type": "authentication_error",
            "message": "invalid x-api-key",
        },
    }


def gemini_auth_error() -> dict:
    """Plausible Google API 403 error body."""
    return {
        "error": {
            "code": 403,
            "message": "API key not valid. Please pass a valid API key.",
            "status": "PERMISSION_DENIED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "API_KEY_INVALID",
                    "domain": "googleapis.com",
                    "metadata": {"service": "generativelanguage.googleapis.com"},
                }
            ],
        }
    }


def openai_auth_error(missing: bool = False) -> dict:
    """Plausible OpenAI 401 error body."""
    if missing:
        return {
            "error": {
                "message": "No API key provided. You can find your API key at https://platform.openai.com/account/api-keys.",
                "type": "invalid_request_error",
                "param": None,
                "code": None,
            }
        }
    return {
        "error": {
            "message": "Incorrect API key provided. You can find your API key at https://platform.openai.com/account/api-keys.",
            "type": "invalid_request_error",
            "param": None,
            "code": "invalid_api_key",
        }
    }

