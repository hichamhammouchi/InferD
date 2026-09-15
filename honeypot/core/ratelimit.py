"""Per-source-IP rate limiting with independent soft and hard token buckets."""

import asyncio
import time
from dataclasses import dataclass, field

from honeypot.core.config import settings


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


@dataclass
class RateBuckets:
    soft: TokenBucket
    hard: TokenBucket


_buckets: dict[str, RateBuckets] = {}
_stream_semaphores: dict[str, asyncio.Semaphore] = {}


def _get_buckets(source_ip: str) -> RateBuckets:
    if source_ip not in _buckets:
        soft = max(settings.rate_limit_soft_rpm, 1)
        hard = max(settings.rate_limit_hard_rpm, soft)
        _buckets[source_ip] = RateBuckets(
            soft=TokenBucket(float(soft), soft / 60.0),
            hard=TokenBucket(float(hard), hard / 60.0),
        )
    return _buckets[source_ip]


def get_stream_semaphore(source_ip: str) -> asyncio.Semaphore:
    if source_ip not in _stream_semaphores:
        _stream_semaphores[source_ip] = asyncio.Semaphore(settings.max_streaming_per_ip)
    return _stream_semaphores[source_ip]


async def check(source_ip: str) -> tuple[bool, float]:
    """Return ``(allowed, injected_latency_seconds)`` for one request."""
    buckets = _get_buckets(source_ip)
    if not buckets.hard.consume():
        return False, 0.0
    if not buckets.soft.consume():
        latency = settings.rate_limit_latency_ms / 1000.0
        if latency > 0:
            await asyncio.sleep(latency)
        return True, latency
    return True, 0.0


def rate_limit_response() -> dict:
    return {
        "error": {
            "message": (
                "Rate limit reached for requests. "
                "Please wait before making additional requests."
            ),
            "type": "rate_limit_error",
            "param": None,
            "code": "rate_limit_exceeded",
        }
    }
