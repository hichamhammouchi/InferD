"""
Ollama honeypot service - binds on port 11434.
Direct port, no TLS, no Nginx proxy.
"""

from honeypot.core.middleware import create_app
from honeypot.emulators import ollama

app = create_app("ollama")
app.include_router(ollama.router)
