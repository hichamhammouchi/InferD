"""
OpenClaw gateway honeypot service.

Bound by supervisord on port 18789.
FastAPI + Starlette support WebSocket natively - no extra dependencies.
"""

from honeypot.core.middleware import create_app
from honeypot.emulators import openclaw

app = create_app("openclaw")
app.include_router(openclaw.router)
