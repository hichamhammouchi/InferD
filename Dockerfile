# InferD Dockerfile
# Uses python:3.12-slim (not the system Python 3.14 on the host).
# All packages have stable wheels for 3.12 - no compilation needed.
# Security properties:
#   - Non-root user (honeypot) runs all uvicorn processes.
#   - An iptables uid-owner DROP on the host blocks any outbound
#     connection this process attempts, regardless of app-layer bugs.
#   - No shell (/bin/false) for the honeypot user.
#   - supervisord runs as root inside the container (needed to setuid
#     to honeypot for child processes), but makes no network connections.

FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        supervisor \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Honeypot process user. Its numeric UID must match the iptables uid-owner
# rule applied on the host. Override with --build-arg HONEYPOT_UID=<n>.
ARG HONEYPOT_UID=1001
RUN groupadd --gid ${HONEYPOT_UID} honeypot \
 && useradd --uid ${HONEYPOT_UID} --gid ${HONEYPOT_UID} --no-create-home \
            --shell /bin/false --system honeypot

# Application
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot/ ./honeypot/
COPY scripts/ ./scripts/
COPY supervisord.conf /etc/supervisor/conf.d/inferd.conf

# GeoIP database placeholder
# The actual GeoLite2-City.mmdb is downloaded by deploy.sh and mounted
# at /usr/share/GeoIP/ via the volume in docker-compose.yml.
RUN mkdir -p /usr/share/GeoIP

# Data directory
# /data is bind-mounted from the host at runtime (see docker-compose.yml).
# Create it here so the image is self-contained for local testing.
RUN mkdir -p /data/raw /data/db /data/logs \
 && chown -R honeypot:honeypot /data

# Config directory (/etc/inferd is bind-mounted from the host at runtime).
RUN mkdir -p /etc/inferd

# supervisord runs as root to manage child processes (setuid to honeypot).
# Individual uvicorn processes run as the honeypot user.
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
