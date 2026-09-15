"""Central configuration. All tunables live here, loaded once at startup."""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="/etc/inferd/inferd.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Paths
    data_dir: Path = Path("/data")
    db_path: Path = Path("/data/db/honeypot.db")
    raw_log_dir: Path = Path("/data/raw")
    pool_dir: Path = Path("/app/honeypot/response_pools")
    geoip_db_path:     Path = Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
    geoip_asn_db_path: Path = Path("/usr/share/GeoIP/GeoLite2-ASN.mmdb")

    # Service ports
    # Port 8000 is behind Nginx (:443). All others bind directly.
    openai_port:      int = 8000
    ollama_port:      int = 11434
    qdrant_port:      int = 6333
    jupyter_port:     int = 8888
    tgi_port:         int = 8080
    mlflow_port:      int = 5000
    gradio_port:      int = 7860
    # Phase 1 - new emulated services
    vllm_port:        int = 8001
    litellm_port:     int = 4000
    openclaw_port:    int = 18789

    # Rate limiting
    # Slow-path: inject latency below soft limit.
    # Hard limit: return 429 above this.
    rate_limit_soft_rpm: int = 60        # requests/min before latency injection starts
    rate_limit_hard_rpm: int = 300       # requests/min before 429
    rate_limit_latency_ms: int = 2000    # added latency in slow-path (ms)
    max_streaming_per_ip: int = 8        # concurrent streaming connections per IP
    max_request_body_bytes: int = 32 * 1024 * 1024

    # Credential capture
    # Raw presented credentials are not persisted unless explicitly enabled.
    store_raw_auth_keys: bool = False

    # Streaming timing calibration
    # Time-to-first-token: lognormal(mu, sigma) seconds.
    # mu = ln(0.35) ≈ -1.05, sigma = 0.5 → median ~350ms, right-skewed.
    ttft_mu: float = -1.05
    ttft_sigma: float = 0.50
    # Inter-token interval: exponential with this mean (seconds).
    inter_token_mean: float = 0.035
    # Paragraph pause: injected with this probability, uniform(min, max) seconds.
    paragraph_pause_prob: float = 0.08
    paragraph_pause_min: float = 0.30
    paragraph_pause_max: float = 1.20

    # Canary tokens
    # Fraction of responses that embed a canary string.
    canary_injection_rate: float = 0.30



# Singleton - import this everywhere.
settings = Settings()

