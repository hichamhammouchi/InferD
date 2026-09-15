# InferD

**Low-interaction honeypot for AI inference infrastructure.**

InferD emulates AI-serving infrastructure across two attack surfaces and captures
reconnaissance, credential-abuse attempts, vulnerability-shaped probes, and
agentic tool-call sequences. Inference-like response content is sampled from static pools; protocol metadata and lure pages are deterministic or synthetic facade data. Nothing an adversary submits is executed. Non-execution is a property of
the emulator design, and a correctly installed kernel egress rule bound to the honeypot OS user provides an independent backstop against relay or exfiltration.

This repository contains the honeypot core only. Analysis notebooks,
dashboards, and data-export tooling are not part of this artifact. No captured
data is included.

---

## Emulated services (14)

**Surface 1 - self-hosted, direct open ports (9)**

| Service | Port | Primary capture |
|---|---|---|
| Ollama | 11434 | Model enumeration and pull, generation probes |
| vLLM | 8001 | InferD-designated direct port; embedding and remote-media probe telemetry |
| HuggingFace TGI | 8080 | Token-format probes, model enumeration |
| LiteLLM | 4000 | MCP stdio test-connection probes, credential-harvesting payloads, SSRF |
| Qdrant | 6333 | Collection enumeration, poisoning writes, exfiltration |
| Jupyter | 8888 | Token brute force, path enumeration, code payloads |
| MLflow | 5000 | Credential stuffing, experiment and artifact probes |
| Gradio | 7860 | Prompt injection via the predict endpoint |
| OpenClaw | 18789 | Gateway-shaped HTTP/WebSocket and skill-package URL probes |

**Surface 2 - cloud API facades, TLS on :443 (5)**

| Service | Path prefix | Primary capture |
|---|---|---|
| OpenAI-compatible | `/v1/` | Key stuffing, injection, enumeration |
| Anthropic | `/v1/messages` | Key-format probes, multi-turn payloads |
| Gemini | `/v1beta/models/` | Key probes, safety-bypass attempts |
| Assistants | `/v1/threads` | Tool definitions, run reasoning |
| MCP | `/mcp` | Tool-call sequences, OAuth flows |

The five cloud facades are served by one process group behind the reverse proxy.
Each self-hosted service runs as its own group, giving ten supervised process
groups in total. All groups run as the same unprivileged user so a single kernel
egress rule covers every service.

---

## Repository layout

```
inferd/
├── honeypot/                 # Python package (baked into the image)
│   ├── emulators/            # One module per emulated service
│   ├── services/             # FastAPI app wiring (port -> emulator)
│   ├── core/                 # Middleware, logging, auth, anomaly scan, GeoIP enrichment
│   ├── db/                   # SQLite schema (schema.sql)
│   ├── response_pools/       # Static response templates with canary injection
│   └── templates/            # HTML lures (Jupyter, MLflow, Gradio)
├── nginx/nginx.conf          # TLS termination for the cloud facades
├── scripts/
│   ├── deploy.sh             # Bootstrap on a fresh Ubuntu 24.04 host
│   ├── tokens.py             # Honeytoken generation and seed-location registry
├── Dockerfile
├── docker-compose.yml
├── supervisord.conf
├── requirements.txt
└── how-to-setup.md           # Full from-scratch deployment guide
```

---

## Safety and non-execution

- No emulator, service, or core module calls `subprocess`, `eval`, `exec`,
  `pickle.loads`, or any process-spawn primitive. Attacker payloads (including
  the LiteLLM MCP `stdio` command specification) are logged verbatim and never
  run.
- The deployment guide installs a kernel egress rule (`iptables`/`ip6tables`,
  `--uid-owner`, DROP on new non-loopback outbound). Its effectiveness depends
  on the Linux host applying the rule for the same `HONEYPOT_UID` baked into the
  image; verify it during deployment as described in `how-to-setup.md`.
- The decoy holds no production model, production credential, or target datastore, so it exposes no real inference or application asset to compromise.

## Data and storage

No database or captured logs ship with this artifact. The schema lives at
`honeypot/db/schema.sql`, and the honeypot creates an empty SQLite database on
first run at `/data/db/honeypot.db`. Events record the source IP directly.
Authorization and API-key values extracted by the authentication layer are not
persisted raw by default; only a short prefix and SHA-256 hash are retained. Set
`STORE_RAW_AUTH_KEYS=true` only when an approved research protocol explicitly
requires those raw values. Request bodies are research telemetry and are stored
verbatim, so they may themselves contain credentials or other sensitive input.
This artifact does not pseudonymize or rotate IPs. Deployers should apply an
appropriate retention and data-protection policy.

## Quick start

```bash
sudo mkdir -p /data/db /data/raw /data/logs /etc/inferd /usr/share/GeoIP
sudo chown -R 1001:1001 /data
docker build --build-arg HONEYPOT_UID=1001 -t inferd:latest .
docker compose config
docker compose up -d
docker exec inferd supervisorctl status
```

`how-to-setup.md` is the portable, host-agnostic walkthrough (laptop, VM, or
server). `scripts/deploy.sh` is an optional one-shot bootstrap for a public
Ubuntu server. It can provision Let's Encrypt certificates and, only with
`--harden-ssh`, move SSH to port 2222; use those options only when they match
your host.

Port 8001 is an InferD-designated direct port for the vLLM facade. It is not
presented as the conventional or default upstream vLLM port.


## Contact

**[Hicham Hammouchi](mailto:hicham.hammouchi@uni.lu)** and **Gabriele Lenzini**  
Interdisciplinary Centre for Security, Reliability and Trust (SnT)  
University of Luxembourg

## Licensing

The source code in this repository is licensed under the [MIT License](LICENSE).

Unless otherwise stated, documentation and non-code research artifacts are provided under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

## Disclaimer

InferD is released for cybersecurity research, measurement, and defensive experimentation.

The framework is designed around **deception without inference**: attacker-supplied code, tool calls, URLs, and model requests are captured as intent and are not executed or forwarded by the honeypot.

Some response pools intentionally contain synthetic credentials, API keys, tokens, payloads, and
other secret-shaped or attack-shaped content for deception and testing purposes. These values are
not intended to provide access to real systems or services.

Users are responsible for deploying and operating InferD in accordance with applicable laws,
institutional policies, network policies, and ethical research requirements.

## Citation

If you use InferD, please consider citing our paper:

```bibtex
@inproceedings{hammouchi2026inferd,
  author    = {Hicham Hammouchi and Gabriele Lenzini},
  title     = {InferD: A Honeypot Framework for AI Inference Infrastructure},
  booktitle = {Proceedings of the 19th Workshop on Artificial Intelligence and Security},
  year      = {2026},
  publisher = {ACM},
  doi       = {10.1145/3847352.3848091}
}
