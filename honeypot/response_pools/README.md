# response_pools/

Static JSON files sampled by `core/pool.py` to generate fake but realistic responses. Nothing here is ever evaluated, pools are read at startup and sampled at request time.

---

## Files

| File | Used by | Contents |
|---|---|---|
| `chat_completions.json` | openai, anthropic, gemini, assistants | Array of fake assistant message strings with `{VARIANT:a\|b\|c}` placeholders |
| `ollama_generate.json` | ollama | Fake generation responses in Ollama NDJSON format |
| `tgi_generate.json` | tgi | Fake HuggingFace TGI streaming responses |
| `embeddings.json` | openai (`text-embedding-3-small`, 1536-dim) | Pre-computed fake embedding vectors |
| `embeddings_3072.json` | OpenAI large, vLLM, Ollama (3072-dim) | Pre-computed fake embedding vectors |
| `embeddings_768.json` | Gemini (768-dim) | Pre-computed fake embedding vectors |
| `tool_results.json` | mcp | Per-tool fake results keyed by tool name (`read_file`, `execute_code`, ...) |
| `jailbreak.json` | openai, anthropic | Fake refusal responses used when jailbreak patterns detected |
| `credential_probe.json` | openai, assistants | Fake responses to credential-seeking prompts |
| `persona_injection.json` | openai, anthropic | Fake responses to persona injection attempts |
| `prompt_extraction.json` | openai, assistants | Fake responses to system-prompt extraction attempts |

---

## Variant syntax

Responses use `{VARIANT:option1|option2|option3}` to prevent identical responses across sessions, which would make the honeypot easily fingerprint-detectable:

```json
"{VARIANT:Here's|Below is|Here is} a Python function that {VARIANT:parses|extracts|processes} JSON..."
```

`pool.py` expands all variants randomly at sample time.

## Checked-in pool counts

The checked-in pools contain 25 chat responses, 6 credential-probe responses,
8 jailbreak responses, 25 Ollama responses, 6 persona-injection responses,
7 prompt-extraction responses, 22 TGI responses, 21 tool-result variants, and
10 vectors in each embedding pool.

---

## Canary injection

Canary-capable response paths issue a per-session token according to
`CANARY_INJECTION_RATE` and persist it before returning the response. Pool
samplers embed the token only when the caller supplies one. If the token later
reappears in an inbound request, InferD links the echo to the issuing session.

---

## Adding a new pool

1. Create a JSON file following the format of an existing pool.
2. Add a sampling function in `core/pool.py`.
3. Call it from the relevant emulator instead of a hardcoded string.

Pools are baked into the image and loaded once per process. Rebuild and restart
the image after changing a pool file.
