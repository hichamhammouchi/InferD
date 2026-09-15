"""LiteLLM proxy honeypot service - binds on port 4000."""

from honeypot.core.middleware import create_app
from honeypot.emulators import litellm_proxy

app = create_app("litellm")
app.include_router(litellm_proxy.router)
