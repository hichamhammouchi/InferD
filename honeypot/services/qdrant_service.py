"""Qdrant honeypot service - binds on port 6333. Direct, no TLS."""
from honeypot.core.middleware import create_app
from honeypot.emulators import qdrant

app = create_app("qdrant")
app.include_router(qdrant.router)
