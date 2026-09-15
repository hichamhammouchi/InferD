"""Gradio lure service - binds on port 7860. Direct, no TLS."""
from honeypot.core.middleware import create_app
from honeypot.emulators import gradio

app = create_app("gradio")
app.include_router(gradio.router)
