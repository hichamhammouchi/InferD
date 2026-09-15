"""Jupyter lure service - binds on port 8888. Direct, no TLS."""
from honeypot.core.middleware import create_app
from honeypot.emulators import jupyter

app = create_app("jupyter")
app.include_router(jupyter.router)
