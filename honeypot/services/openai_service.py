"""
OpenAI / Assistants / MCP honeypot service - binds on port 8000.
Reached externally via Nginx on port 443 (TLS terminated).

All three emulators share one port because this is how api.openai.com
works: /v1/*, /v1/assistants, /v1/threads are all on the same host.
MCP is placed at /mcp/* on the same service for the same reason -
a realistic AI backend would serve agent tooling alongside the API.
"""

from honeypot.core.middleware import create_app
from honeypot.emulators import anthropic, assistants, gemini, mcp, openai

app = create_app("openai")

# OpenAI core API routes (/v1/models, /v1/chat/completions, etc.)
app.include_router(openai.router)

# Assistants API stateful routes (/v1/threads/*, /v1/assistants/*)
app.include_router(assistants.router)

# MCP server routes - both SSE legacy and Streamable HTTP transports.
app.include_router(mcp.router)

# Anthropic Messages API (/v1/messages, /v1/messages/batches, ...)
# NOTE: Anthropic's /v1/models is mounted here too; FastAPI uses first-registered
# match, so OpenAI's GET /v1/models (registered above) wins for that path.
# Anthropic model enumeration is captured via /v1/models returning combined list.
app.include_router(anthropic.router)

# Google Gemini API (/v1beta/models/{model}:generateContent, etc.)
# Uses distinct /v1beta/ prefix so no OpenAI route conflicts.
app.include_router(gemini.router)
