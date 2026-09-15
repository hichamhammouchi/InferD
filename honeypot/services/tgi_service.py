"""HuggingFace TGI lure service - binds on port 8080. Direct, no TLS."""
from honeypot.core.middleware import create_app
from honeypot.emulators import tgi

app = create_app("tgi")
app.include_router(tgi.router)
