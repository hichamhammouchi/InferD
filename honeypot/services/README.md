# services/

Each file creates a FastAPI app via `create_app()`, mounts one or more emulator routers, and is the entry point for a single uvicorn process managed by supervisord.

---

## Service map

| Service file | Emulators mounted | Port | Notes |
|---|---|---|---|
| `openai_service.py` | openai + assistants + mcp + anthropic + gemini | 8000 | Behind Nginx :443; first-registered router wins on path conflicts |
| `ollama_service.py` | ollama | 11434 | Direct, no TLS |
| `vllm_service.py` | vllm | 8001 | Direct, no TLS; InferD-designated port |
| `jupyter_service.py` | jupyter | 8888 | Direct, no TLS |
| `tgi_service.py` | tgi | 8080 | Direct, no TLS |
| `mlflow_service.py` | mlflow | 5000 | Direct, no TLS |
| `qdrant_service.py` | qdrant | 6333 | Direct, no TLS |
| `gradio_service.py` | gradio | 7860 | Direct, no TLS |
| `litellm_service.py` | litellm_proxy | 4000 | Direct, no TLS |
| `openclaw_service.py` | openclaw | 18789 | Direct, no TLS; also WebSocket |

---


Emulators (`../emulators/`) are plain `APIRouter` objects. Keeping them router-only means:

- Each emulator can be tested standalone without binding a port.
- Multiple emulators can share one port (the `openai_service.py` pattern) without coupling their code.
- supervisord manages processes at the service level, not the emulator level.

---

## openai_service.py: mount order

```python
app.include_router(openai.router)      # GET /v1/models - registered first
app.include_router(assistants.router)  # POST /v1/threads
app.include_router(mcp.router)         # POST /mcp, OAuth routes
app.include_router(anthropic.router)   # POST /v1/messages
app.include_router(gemini.router)      # POST /v1beta/models/...
```

FastAPI uses first-match routing. If two routers register the same path, the first one wins. The OpenAI router owns `/v1/models`, so Anthropic probers using `x-api-key` hit the OpenAI handler, which is why both `authorization` and `x-api-key` headers are checked there.
