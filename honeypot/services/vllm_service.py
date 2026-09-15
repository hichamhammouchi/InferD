"""vLLM inference server honeypot service - binds on port 8001."""

from honeypot.core.middleware import create_app
from honeypot.emulators import vllm

app = create_app("vllm")
app.include_router(vllm.router)
