"""
Response pool loader and sampler for InferD.

Pools are loaded once at process startup into memory and kept there.
At request time, a random entry is selected and per-request fields
(id, created timestamp, token counts) are freshly generated so that
no two responses are structurally identical even if the same pool
entry is selected twice.

Pool files (JSON arrays) live in honeypot/response_pools/.
Each service loads only its relevant pool - no process loads all pools.

Variation points in pool entries use the format {VARIANT:a|b|c}
which are resolved at sample time by picking one alternative uniformly.
This prevents exact-string fingerprinting across a corpus of captures.
"""

import json
import random
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from honeypot.core.config import settings

# Regex for variation point resolution
_VARIANT_RE = re.compile(r"\{VARIANT:([^}]+)\}")


def _resolve_variants(text: str) -> str:
    """
    Replace all {VARIANT:a|b|c} markers with a randomly chosen alternative.
    Example: "Here's{VARIANT: how| the way| a method} to..." → "Here's how to..."
    """
    def _pick(m: re.Match) -> str:
        options = m.group(1).split("|")
        return random.choice(options)
    return _VARIANT_RE.sub(_pick, text)


# Pool loading

@lru_cache(maxsize=None)
def _load(filename: str) -> list[dict[str, Any]]:
    """Load a pool JSON file. Cached after first load (lru_cache)."""
    path = settings.pool_dir / filename
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# Samplers

def sample_chat_completion(model: str = "gpt-4o") -> dict[str, Any]:
    """
    Return a complete (non-streaming) chat completion response dict.
    All per-request fields are freshly generated.
    """
    pool = _load("chat_completions.json")
    if not pool:
        content = "I'm sorry, I can't help with that right now."
    else:
        entry = random.choice(pool)
        content = _resolve_variants(entry["content"])

    import time
    import uuid
    prompt_tokens = random.randint(15, 120)
    completion_tokens = max(10, len(content.split()))

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
        "system_fingerprint": f"fp_{uuid.uuid4().hex[:10]}",
    }


def sample_chat_content(prompt: str = "", canary_token: str = "") -> str:
    """
    Return just the text content for streaming, with optional canary embedded.

    When `prompt` is provided, the dispatcher selects a thematically
    appropriate sub-pool, improving response coherence for agentic clients.
    Falls back to the default chat_completions pool on no match.
    """
    from honeypot.core import dispatcher
    pool_file = dispatcher.route(prompt) if prompt else "chat_completions.json"

    pool = _load(pool_file)
    if not pool:
        # Fallback to default pool if sub-pool file is missing
        pool = _load("chat_completions.json") or []

    if not pool:
        content = "I understand your request. Let me help you with that."
    else:
        entry = random.choice(pool)
        content = _resolve_variants(entry["content"])

    if canary_token:
        from honeypot.core.canary import embed
        content = embed(canary_token, content)

    return content


def sample_ollama_response(model: str = "llama3") -> dict[str, Any]:
    """Return a complete (non-streaming) Ollama generate response."""
    pool = _load("ollama_generate.json")
    if not pool:
        response_text = "Sure, I can help with that."
    else:
        entry = random.choice(pool)
        response_text = _resolve_variants(entry["response"])

    import time
    now_ns = int(time.time() * 1e9)
    tokens = len(response_text.split())

    return {
        "model": model,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime()),
        "response": response_text,
        "done": True,
        "done_reason": "stop",
        "context": [random.randint(1000, 50000) for _ in range(random.randint(10, 30))],
        "total_duration": random.randint(1000000000, 8000000000),
        "load_duration": random.randint(10000000, 100000000),
        "prompt_eval_count": random.randint(10, 80),
        "prompt_eval_duration": random.randint(50000000, 500000000),
        "eval_count": tokens,
        "eval_duration": random.randint(500000000, 4000000000),
    }


def sample_ollama_content(canary_token: str = "") -> str:
    """Return just the text for streaming Ollama responses, with optional canary."""
    pool = _load("ollama_generate.json")
    if not pool:
        content = "I can help you with that."
    else:
        entry = random.choice(pool)
        content = _resolve_variants(entry["response"])
    if canary_token:
        from honeypot.core.canary import embed
        content = embed(canary_token, content)
    return content


def sample_tgi_response(canary_token: str = "") -> str:
    """Return generated text for HF TGI endpoint, with optional canary."""
    pool = _load("tgi_generate.json")
    if not pool:
        content = "Here is the generated response for your input."
    else:
        entry = random.choice(pool)
        content = _resolve_variants(entry["generated_text"])
    if canary_token:
        from honeypot.core.canary import embed
        content = embed(canary_token, content)
    return content


def sample_tool_result(tool_name: str) -> Any:
    """
    Return a fake tool result for an MCP tool call.
    Returns the result value (already resolved, ready for JSON encoding).
    """
    pool = _load("tool_results.json")
    if not pool:
        return {"output": "Operation completed successfully."}

    # tool_results.json is a dict keyed by tool name.
    if isinstance(pool, list):
        # Fallback if file was structured as a list.
        return {"output": "Done."}

    results = pool.get(tool_name, [{"output": "Operation completed."}])
    result = random.choice(results) if isinstance(results, list) else results
    return result


def sample_anthropic_content(canary_token: str = "") -> str:
    """
    Return content text for an Anthropic Messages API response.
    Reuses the chat_completions pool - the prose is format-agnostic.
    """
    return sample_chat_content(canary_token=canary_token)


def sample_gemini_content(canary_token: str = "") -> str:
    """
    Return content text for a Gemini generateContent response.
    Reuses the chat_completions pool - the prose is format-agnostic.
    """
    return sample_chat_content(canary_token=canary_token)


def sample_embedding(dims: int = 1536) -> list[float]:
    """
    Return a pre-built fake embedding vector sampled from the pre-computed pool.

    Pool files (ship pre-generated in honeypot/response_pools/):
      embeddings.json      - 10 × 1536d  (OpenAI text-embedding-3-small, ada-002)
      embeddings_3072.json - 10 × 3072d  (OpenAI text-embedding-3-large)
      embeddings_768.json  - 10 × 768d   (Gemini text-embedding-004, Nomic)

    Always sampling from a fixed pool (not fresh random vectors) prevents
    the trivial fingerprint where the same text returns a different vector
    on every call.
    """
    filename_map = {
        768:  "embeddings_768.json",
        1536: "embeddings.json",
        3072: "embeddings_3072.json",
    }
    filename = filename_map.get(dims)
    if filename is None:
        raise ValueError(f"No static embedding pool for dimension {dims}")
    pool = _load(filename)
    if pool:
        vec = random.choice(pool)
        if len(vec) == dims:
            return vec

    # Fallback: deterministic random unit vector (used if pool files missing).
    import math
    vec = [random.gauss(0, 1) for _ in range(dims)]
    magnitude = math.sqrt(sum(x * x for x in vec))
    return [x / magnitude for x in vec] if magnitude > 0 else vec
