"""
Structural anomaly detection for InferD.

Scans every inbound request for patterns that are structurally unusual
regardless of any known CVE. Produces a comma-separated anomaly_flags
string stored in events.anomaly_flags.

Design principle: CVE-independent. These flags fire even for zero-days
because they detect *structure*, not specific exploit signatures. When a
new CVE is later published, the anomaly flags in historical events become
retroactive pre-disclosure evidence.

Called from middleware on every request, before route handlers.
Cost: one pass over the raw body bytes + header inspection. < 1ms.
"""

import base64
import re
from typing import Any

# Regex helpers

_BASE64_RE   = re.compile(r"^[A-Za-z0-9+/]{60,}={0,2}$")
_SHELL_RE    = re.compile(r"[;&|`$(){}<>]|&&|\|\|")
_URL_RE      = re.compile(r"https?://", re.IGNORECASE)
_CODE_RE     = re.compile(
    r"\b(import |eval\(|exec\(|__import__|subprocess\.|os\.system|"
    r"open\(|pickle\.loads|torch\.load|base64\.decode)\b"
)
_SQL_RE      = re.compile(
    r"\b(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|SELECT\s+\*|"
    r"OR\s+1=1|AND\s+1=1|xp_cmdshell|information_schema)\b",
    re.IGNORECASE,
)
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\")
_PRIV_KEYS    = frozenset({
    "senderisowner", "isadmin", "isroot", "isowner",
    "role", "admin", "elevated", "superuser", "privileged",
})
_COMMAND_KEYS = frozenset({
    "command", "cmd", "exec", "execute", "entrypoint",
    "args", "argv", "spawn", "run", "shell", "invoke",
})
_MULTIMODAL_KEYS = frozenset({
    "video_url", "image_url", "audio_url", "file_url",
    "media_url", "attachment_url",
})

# Pickle protocol magic bytes (protocol 2-5)
_PICKLE_MAGIC = {b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"}

# Maximum single-field size before flagging
_MAX_FIELD_BYTES = 50000


# Public API

def scan(
    body: bytes,
    parsed: dict[str, Any] | None,
    headers: dict[str, str],
    endpoint: str,
) -> str:
    """
    Scan a request for structural anomalies.

    Returns a comma-separated string of flag names, or empty string if clean.
    Each flag name is lowercase with underscores, e.g. "base64_payload,shell_metachar".
    """
    flags: list[str] = []

    # Raw body checks
    if body:
        # Pickle magic bytes
        if any(body[:6].startswith(magic) for magic in _PICKLE_MAGIC):
            flags.append("pickle_magic")

        # Oversized body (not a field, the whole body)
        if len(body) > 5000000:  # 5 MB
            flags.append("oversized_body")

    # Header checks
    origin      = headers.get("origin", "")
    forwarded   = headers.get("x-forwarded-for", "")
    referer     = headers.get("referer", "")
    all_headers = origin + forwarded + referer

    if re.search(r"(127\.0\.0\.1|localhost|::1)", all_headers, re.IGNORECASE):
        flags.append("localhost_origin")

    # JSON field-level checks
    if parsed and isinstance(parsed, dict):
        flags.extend(_scan_fields(parsed, depth=0))

    return ",".join(flags)


def _scan_fields(obj: Any, depth: int) -> list[str]:
    """Recursively scan JSON fields. Depth-limited to 5 to avoid DoS."""
    if depth > 5:
        return []

    flags: set[str] = set()

    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = key.lower()

            # Privilege claim field names
            if key_lower in _PRIV_KEYS and value is True:
                flags.add("privilege_claim")
            elif key_lower in _PRIV_KEYS and isinstance(value, str):
                if value.lower() in ("true", "owner", "admin", "root", "1"):
                    flags.add("privilege_claim")

            # Command/exec field names
            if key_lower in _COMMAND_KEYS:
                flags.add("command_field")

            # Multimodal URL in text-only endpoint
            if key_lower in _MULTIMODAL_KEYS and isinstance(value, str) and value:
                flags.add("multimodal_url")

            # Recurse into value
            if value is not None:
                flags.update(_scan_fields(value, depth + 1))

    elif isinstance(obj, list):
        for item in obj[:50]:  # scan first 50 items
            flags.update(_scan_fields(item, depth + 1))

    elif isinstance(obj, str):
        flags.update(_scan_string(obj))

    return list(flags)


def _scan_string(s: str) -> list[str]:
    """Scan a string value for anomaly signals."""
    if not s or len(s) < 4:
        return []

    flags: set[str] = set()

    # Oversized single field
    if len(s) > _MAX_FIELD_BYTES:
        flags.add("oversized_field")

    # URL in unexpected position
    if _URL_RE.search(s):
        flags.add("unexpected_url_field")

    # Shell metacharacters
    if _SHELL_RE.search(s):
        flags.add("shell_metachar")

    # Code execution patterns
    if _CODE_RE.search(s):
        flags.add("code_in_field")

    # SQL injection patterns
    if _SQL_RE.search(s):
        flags.add("sql_pattern")

    # Path traversal
    if _TRAVERSAL_RE.search(s):
        flags.add("path_traversal")

    # Base64-looking blob (> 80 chars, valid base64 charset)
    if len(s) > 80:
        candidate = s.strip().split()[0] if " " in s else s.strip()
        if _BASE64_RE.match(candidate):
            # Confirm it actually decodes (not just charset match)
            try:
                base64.b64decode(candidate + "==", validate=True)
                flags.add("base64_payload")
            except Exception:
                pass

    return list(flags)

