"""
Keyword-based prompt router for InferD response pools.

Maps inbound prompt text to a thematically appropriate response pool file,
improving response coherence for agentic clients that reason over content.

Design: purely regex-based, no LLM. Runs in < 0.1ms. Falls back to the
default chat_completions pool on no match. Patterns are ordered by
specificity - first match wins.

Used by pool.sample_chat_content(prompt=...) when a prompt is provided.
"""

import re

# Pattern table
# (regex, pool_filename) - ordered: most specific first, fallback last.
# All patterns are case-insensitive.

_ROUTES: list[tuple[re.Pattern, str]] = [
    # System prompt extraction probes
    # Highest value: agent is trying to exfiltrate instructions.
    (re.compile(
        r"(what are your|show me your|reveal your|repeat your|"
        r"print your|output your|display your|give me your|tell me your)"
        r".{0,40}(system prompt|instructions|rules|guidelines|"
        r"initial prompt|base prompt|hidden prompt|configuration|"
        r"system message|context|constraints)",
        re.IGNORECASE,
    ), "prompt_extraction.json"),

    (re.compile(
        r"(ignore|forget|disregard|override).{0,30}"
        r"(system prompt|previous instructions|above instructions|"
        r"earlier instructions|your rules|your guidelines|your constraints)",
        re.IGNORECASE,
    ), "prompt_extraction.json"),

    # Jailbreak attempts
    (re.compile(
        r"(DAN|Do Anything Now|jailbreak|developer mode|"
        r"unrestricted mode|no restrictions|bypass.{0,20}filter|"
        r"ignore.{0,20}(previous|prior).{0,20}(instruction|prompt|rule)|"
        r"you are now|pretend you have no|act as if you have no|"
        r"without (any|ethical|moral) (restrictions|constraints|limits))",
        re.IGNORECASE,
    ), "jailbreak.json"),

    # Credential and secret probes
    (re.compile(
        r"(api.?key|secret.?key|access.?token|bearer.?token|"
        r"password|passphrase|credential|auth.?token|"
        r"private.?key|service.?account|jwt.?token|"
        r"(show|give|reveal|print|output).{0,20}(key|token|secret|password)|"
        r"what.?is.?the.?(key|token|secret|password))",
        re.IGNORECASE,
    ), "credential_probe.json"),

    # Persona injection
    (re.compile(
        r"^.{0,20}(you are|act as|pretend (to be|you are)|"
        r"roleplay as|simulate|imagine you are|behave as|"
        r"respond as|speak as|write as).{0,60}$",
        re.IGNORECASE,
    ), "persona_injection.json"),

    (re.compile(
        r"(from now on|henceforth|starting now).{0,40}"
        r"(you are|you will be|act as|respond as)",
        re.IGNORECASE,
    ), "persona_injection.json"),

    # Code requests
    (re.compile(
        r"(write|generate|create|implement|build|code|"
        r"show me|give me|produce).{0,30}"
        r"(function|script|program|class|snippet|code|"
        r"implementation|example|solution).{0,30}"
        r"(in|using|with|for)?.{0,20}"
        r"(python|javascript|typescript|go|rust|bash|sql|java|c\+\+|"
        r"ruby|php|swift|kotlin)|"
        r"(def |import |class |```python|```js|```bash|```sql|"
        r"how (to|do (I|you)) (implement|write|build|create|use))",
        re.IGNORECASE,
    ), "chat_completions.json"),
]

# Default pool - used when no pattern matches
_DEFAULT_POOL = "chat_completions.json"


# Public API

def route(prompt: str) -> str:
    """
    Return the pool filename most appropriate for the given prompt.
    First match wins. Returns default pool on no match or empty prompt.
    """
    if not prompt or len(prompt) < 5:
        return _DEFAULT_POOL

    # Truncate to first 500 chars for routing - rest is captured in payload_json
    text = prompt[:500]

    for pattern, pool_file in _ROUTES:
        if pattern.search(text):
            return pool_file

    return _DEFAULT_POOL
