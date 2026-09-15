"""MLflow lure service - binds on port 5000. Direct, no TLS."""
from honeypot.core.middleware import create_app
from honeypot.emulators import mlflow

app = create_app("mlflow")
app.include_router(mlflow.router)
