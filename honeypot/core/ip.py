"""
Real IP extraction for InferD.

Two cases handled:

1. TLS-terminated ports (443 → Nginx → :8000):
   The socket peer is always 127.0.0.1 (the Nginx proxy).
   Real attacker IP is in the X-Real-IP header set by Nginx.

2. Direct ports (11434, 6333, 8888, 8080, 5000, 7860):
   The container runs with --network host, so request.client.host
   is the actual attacker IP as seen at the host NIC.

IPv4 and IPv6 are both handled. IPv4-mapped IPv6 addresses
(::ffff:1.2.3.4) are normalised to plain IPv4.
"""

import ipaddress
from starlette.requests import Request


def extract_real_ip(request: Request) -> str:
    """
    Return the real attacker IP as a normalised string.
    Never raises - returns '0.0.0.0' if extraction fails entirely.
    """
    # TLS-terminated: trust X-Real-IP only when the TCP peer is Nginx (127.0.0.1).
    # Prevents attackers hitting port 8000 directly from injecting a fake X-Real-IP.
    peer = request.client.host if request.client else ""
    if peer == "127.0.0.1":
        x_real_ip = request.headers.get("x-real-ip", "").strip()
        if x_real_ip:
            return _normalise(x_real_ip)

    # Direct port: raw socket peer.
    if request.client and request.client.host:
        return _normalise(request.client.host)

    return "0.0.0.0"


def _normalise(raw: str) -> str:
    """
    Normalise an IP address string.
    Strips IPv4-mapped IPv6 prefix (::ffff:) and validates the result.
    """
    # Strip port if present (e.g. "[::1]:12345" or "1.2.3.4:5678")
    raw = raw.strip()
    if raw.startswith("["):
        # IPv6 with port: [addr]:port
        raw = raw.split("]")[0].lstrip("[")
    elif raw.count(":") == 1:
        # IPv4 with port: addr:port
        raw = raw.split(":")[0]

    try:
        addr = ipaddress.ip_address(raw)
        # Unwrap IPv4-mapped IPv6
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return "0.0.0.0"


def is_private(ip: str) -> bool:
    """Return True if the IP is RFC-1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
