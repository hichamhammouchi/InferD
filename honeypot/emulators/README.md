# emulators/

One Python module per emulated service. Each module exports a FastAPI `router` that is mounted by the corresponding service in `../services/`.

---

## Service map

| Module | Port | Auth | CVEs targeted | Primary research value |
|---|---|---|---|---|
| `ollama.py` | 11434 | none | - | Model pull corpus, prompt payloads, UA fingerprinting |
| `vllm.py` | 8001 | none | CVE-labelled probe fields | Embedding/video probe capture, Prometheus scraping behaviour |
| `jupyter.py` | 8888 | token | - | Token brute-force corpus, code execution payloads |
| `tgi.py` | 8080 | HF token | - | HF token format, `/tokenize` downstream task reveal |
| `mlflow.py` | 5000 | password | - | Credential stuffing, artifact download probes |
| `qdrant.py` | 6333 | none | - | RAG poisoning - upserted vectors logged verbatim |
| `gradio.py` | 7860 | none | - | Jailbreak prompts, prompt injection |
| `litellm_proxy.py` | 4000 | API key | historical vulnerable-looking routes | Python, SQL, SSRF, and MCP command-injection probe capture |
| `openclaw.py` | 18789 | password | Probe-class telemetry | Gateway, WebSocket, and skill package URL probes |
| `openai.py` | 443 | honeytoken | - | Key stuffing, prompt injection, system prompt exfil |
| `assistants.py` | 443 | honeytoken | - | Tool definitions, `submit_tool_outputs` (agent reasoning) |
| `mcp.py` | 443 | honeytoken / OAuth | - | Tool-call sequences, OAuth redirect URIs, Bearer honeytokens |
| `anthropic.py` | 443 | honeytoken | - | `x-api-key` probes, multi-turn payloads |
| `gemini.py` | 443 | honeytoken | - | `x-goog-api-key` probes, `safetySettings` bypass attempts |

---

## Design rules

Every emulator follows the same contract:

1. **Log before returning**: the canonical JSONL event is appended before the response is returned; SQLite indexing is queued asynchronously.
2. **Never evaluate**: tool arguments, code payloads, SQL, and URLs are logged verbatim and never executed or forwarded.
3. **Static fake results**: responses are sampled from `../response_pools/` or generated deterministically; no external calls.
4. **Consistent extras dict**: operation-specific fields go into `extras` in the canonical JSONL record; SQLite stores the shared event fields.

---

## Examples

### Ollama - model pull (reveals attacker's target model)

```bash
curl -s http://YOUR_SERVER:11434/api/pull \
  -d '{"name":"llama3:70b-instruct","stream":false}'
# Logged: model_requested="llama3:70b-instruct"
```

### vLLM - embedding-field probe capture

```bash
curl -s http://YOUR_SERVER:8001/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"meta-llama/Llama-3.1-8B-Instruct","prompt":"test","prompt_embeds":"gASV..."}'
# anomaly_flags: pickle_magic,base64_payload - logged, never loaded
```

### MCP - initialize + tool call (spec 2025-11-25)

```bash
# Initialize
curl -s -X POST https://localhost/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"my-agent","version":"1.0"}}}'

# Call a tool
curl -s -X POST https://localhost/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_code","arguments":{"code":"import os; os.listdir('/')","language":"python"}}}'
# Logged: tool_name, tool_arguments (full code), tool_call_seq
```

### Assistants - full agentic run (exposes requires_action)

```bash
# 1. Create thread
THREAD=$(curl -s -X POST https://localhost/v1/threads \
  -H "Authorization: Bearer sk-inf-..." | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 2. Add message
curl -s -X POST https://localhost/v1/threads/$THREAD/messages \
  -H "Authorization: Bearer sk-inf-..." \
  -d '{"role":"user","content":"Search the knowledge base for our deployment keys"}'

# 3. Create run (poll twice to reach requires_action)
RUN=$(curl -s -X POST https://localhost/v1/threads/$THREAD/runs \
  -H "Authorization: Bearer sk-inf-..." \
  -d '{"model":"gpt-4o"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 4. Poll → in_progress → requires_action (tool_calls exposed)
curl -s https://localhost/v1/threads/$THREAD/runs/$RUN \
  -H "Authorization: Bearer sk-inf-..." | python3 -m json.tool

# 5. Submit tool outputs - PRIMARY capture
curl -s -X POST https://localhost/v1/threads/$THREAD/runs/$RUN/submit_tool_outputs \
  -H "Authorization: Bearer sk-inf-..." \
  -d '{"tool_outputs":[{"tool_call_id":"call_xxx","output":"found: prod_key=AKIAIOSFODNN7EXAMPLE"}]}'
# Logged verbatim - this is what the agent computed
```

### OpenClaw - localhost-header probe capture

```bash
curl -s http://YOUR_SERVER:18789/api/config \
  -H "Origin: http://localhost" \
  -H "X-Forwarded-For: 127.0.0.1"
# logged as a localhost-header probe
```
