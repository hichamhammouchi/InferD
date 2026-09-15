"""
Calibrated streaming response utilities for InferD.

All streaming emulates GPT-4-class inference latency distributions
derived from published Artificial Analysis benchmarks:

  Time-to-first-token (TTFT):
      Lognormal(mu=-1.05, sigma=0.5) → median ~350ms, right-skewed tail.

  Inter-token interval:
      Exponential(mean=35ms) - matches observed ~28 tok/s average with
      natural variance. Tokens here are whitespace-delimited words, not
      BPE tokens; word-level granularity avoids per-character overhead
      while producing realistic chunk sizes for SSE/NDJSON.

  Paragraph pauses:
      With probability 0.08, inject uniform(300ms, 1200ms) after a
      sentence-ending punctuation mark. Simulates the "thinking" pauses
      visible in real model outputs between paragraphs.

No real inference happens. The timing is purely asyncio.sleep().
A sufficiently sophisticated timing-analysis attacker could detect
deviations from real inference distributions. The current calibration prevents
detection by anything short of dedicated timing analysis.
"""

import asyncio
import random
from collections.abc import AsyncGenerator
from typing import AsyncIterator

from honeypot.core.config import settings

# Sentence-ending punctuation that may precede a paragraph pause.
_SENTENCE_ENDINGS = frozenset(".!?")


async def _ttft() -> None:
    """Sleep for a lognormally-distributed time-to-first-token."""
    delay = random.lognormvariate(settings.ttft_mu, settings.ttft_sigma)
    delay = max(0.05, min(delay, 4.0))   # clamp: 50ms-4s
    await asyncio.sleep(delay)


async def token_stream(text: str) -> AsyncGenerator[str, None]:
    """
    Async generator that yields whitespace-delimited words from *text*
    with calibrated inter-token delays.

    Usage:
        async for token in token_stream(content):
            yield f"data: {build_chunk(token)}\\n\\n"
    """
    await _ttft()

    words = text.split(" ")
    for i, word in enumerate(words):
        # Re-attach trailing space except on the last word.
        chunk = word if i == len(words) - 1 else word + " "
        yield chunk

        # Paragraph pause - only after sentence-ending punctuation.
        stripped = word.rstrip()
        if stripped and stripped[-1] in _SENTENCE_ENDINGS:
            if random.random() < settings.paragraph_pause_prob:
                pause = random.uniform(
                    settings.paragraph_pause_min,
                    settings.paragraph_pause_max,
                )
                await asyncio.sleep(pause)
                continue   # Skip normal inter-token delay after a long pause.

        interval = random.expovariate(1.0 / settings.inter_token_mean)
        interval = max(0.005, min(interval, 0.5))   # clamp: 5ms-500ms
        await asyncio.sleep(interval)


async def ollama_ndjson_stream(
    text: str,
    model: str,
    done_stats: dict,
) -> AsyncGenerator[str, None]:
    """
    Yield Ollama-format NDJSON lines.
    Each intermediate line: {"model":..., "response":" token", "done":false}
    Final line:             {"model":..., "response":"", "done":true, ...stats}
    """
    import json
    import time

    created_at = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())

    async for token in token_stream(text):
        line = json.dumps(
            {"model": model, "created_at": created_at, "response": token, "done": False}
        )
        yield line + "\n"

    # Final done line with stats.
    final = {"model": model, "created_at": created_at, "response": "", "done": True,
             "done_reason": "stop"}
    final.update(done_stats)
    yield json.dumps(final) + "\n"


async def anthropic_sse_stream(
    text: str,
    model: str,
    message_id: str,
    input_tokens: int,
) -> AsyncGenerator[str, None]:
    """
    Yield Anthropic Messages API typed SSE events.

    Sequence:
        message_start → content_block_start → ping →
        content_block_delta* → content_block_stop →
        message_delta → message_stop

    Each line is:  event: <type>\\ndata: <json>\\n\\n
    """
    import json

    def _evt(event_type: str, data: dict) -> str:
        return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

    # Preamble
    yield _evt("message_start", {
        "type": "message_start",
        "message": {
            "id": message_id,
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": model,
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": input_tokens, "output_tokens": 1},
        },
    })
    yield _evt("content_block_start", {
        "type": "content_block_start",
        "index": 0,
        "content_block": {"type": "text", "text": ""},
    })
    yield _evt("ping", {"type": "ping"})

    # Token stream
    await _ttft()

    output_tokens = 0
    words = text.split(" ")
    for i, word in enumerate(words):
        chunk = word if i == len(words) - 1 else word + " "
        output_tokens += 1

        yield _evt("content_block_delta", {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": chunk},
        })

        stripped = word.rstrip()
        if stripped and stripped[-1] in _SENTENCE_ENDINGS:
            if random.random() < settings.paragraph_pause_prob:
                pause = random.uniform(settings.paragraph_pause_min, settings.paragraph_pause_max)
                await asyncio.sleep(pause)
                continue

        interval = random.expovariate(1.0 / settings.inter_token_mean)
        interval = max(0.005, min(interval, 0.5))
        await asyncio.sleep(interval)

    # Epilogue
    yield _evt("content_block_stop", {"type": "content_block_stop", "index": 0})
    yield _evt("message_delta", {
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
        "usage": {"output_tokens": output_tokens},
    })
    yield _evt("message_stop", {"type": "message_stop"})


_GEMINI_SAFETY_RATINGS = [
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",  "probability": "NEGLIGIBLE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH",        "probability": "NEGLIGIBLE"},
    {"category": "HARM_CATEGORY_HARASSMENT",         "probability": "NEGLIGIBLE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT",  "probability": "NEGLIGIBLE"},
]


async def gemini_sse_stream(
    text: str,
    model: str,
    prompt_tokens: int,
) -> AsyncGenerator[str, None]:
    """
    Yield Google Gemini streamGenerateContent SSE events.

    Gemini sends larger word-groups per chunk than OpenAI (typical chunk ≈ 5-12 words).
    Each event is:  data: <json>\\n\\n   (no event: type line - Gemini uses unnamed events).
    """
    import json

    await _ttft()

    words = text.split(" ")
    chunk_size = random.randint(5, 12)
    total_out = 0

    for i in range(0, len(words), chunk_size):
        chunk_words = words[i : i + chunk_size]
        is_last = (i + chunk_size) >= len(words)
        chunk_text = " ".join(chunk_words) + ("" if is_last else " ")
        total_out += len(chunk_words)

        data = {
            "candidates": [
                {
                    "content": {"parts": [{"text": chunk_text}], "role": "model"},
                    "finishReason": "STOP" if is_last else None,
                    "index": 0,
                    "safetyRatings": _GEMINI_SAFETY_RATINGS,
                }
            ],
            "usageMetadata": {
                "promptTokenCount": prompt_tokens,
                "candidatesTokenCount": total_out,
                "totalTokenCount": prompt_tokens + total_out,
            },
            "modelVersion": model,
        }
        yield f"data: {json.dumps(data)}\n\n"

        if not is_last:
            # Gemini streams at slower cadence than per-word OpenAI
            interval = random.expovariate(1.0 / (settings.inter_token_mean * chunk_size))
            interval = max(0.010, min(interval, 0.8))
            await asyncio.sleep(interval)


async def openai_sse_stream(
    text: str,
    model: str,
    completion_id: str,
    created: int,
) -> AsyncGenerator[str, None]:
    """
    Yield OpenAI-format SSE lines (data: {...}\\n\\n).
    Terminates with data: [DONE]\\n\\n.
    """
    import json

    base = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "system_fingerprint": None,
    }

    async for token in token_stream(text):
        chunk = {**base, "choices": [
            {"index": 0, "delta": {"content": token}, "finish_reason": None}
        ]}
        yield f"data: {json.dumps(chunk)}\n\n"

    # Final chunk - finish_reason = stop, empty delta.
    stop_chunk = {**base, "choices": [
        {"index": 0, "delta": {}, "finish_reason": "stop"}
    ]}
    yield f"data: {json.dumps(stop_chunk)}\n\n"
    yield "data: [DONE]\n\n"

