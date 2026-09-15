# core/

Shared infrastructure used by every emulator. Emulators import from here; nothing here imports from `emulators/`

---

## Request pipeline

Every HTTP request passes through this chain before reaching a route handler:

```
inbound request
      │
      ▼
InferDMiddleware          (middleware.py)
  ├── read raw body once, store in request.state.raw_body
  ├── extract real IP from X-Real-IP or client host
  ├── source IP → request.state.source_ip   (ip.py)
  ├── GeoIP enrichment → request.state.geo           (geoip.py)
  ├── session stitching → request.state.session_id   (middleware.py)
  ├── anomaly scan → request.state.anomaly_flags      (anomaly.py)
  └── canary echo scan → request.state.canary_echo   (canary.py)
      │
      ▼
  route handler (in emulators/)
  ├── parse_auth_header() + check_honeytoken()        (auth.py)
  ├── build EventRecord                               (logger.py)
  ├── log_event() → synchronous JSONL + async queue  (logger.py)
  └── database.enqueue() for ancillary tables         (database.py)
```

---

## Modules

| Module | Exports | Purpose |
|---|---|---|
| `middleware.py` | `InferDMiddleware`, `create_app()` | Request lifecycle, session stitching, lifespan hooks |
| `logger.py` | `EventRecord`, `log_event()`, `now_us()` | Structured event logging to SQLite and raw JSONL |
| `database.py` | `enqueue()`, `get_connection()` | Async write queue over SQLite WAL connection |
| `anomaly.py` | `scan()` | Structural anomaly detection, returns comma-separated flags |
| `auth.py` | `parse_auth_header()`, `check_honeytoken()` | Auth header parsing and honeytoken lookup |
| `canary.py` | `issue_and_persist()`, `lookup_persisted()`, `scan_persisted()` | Canary token lifecycle across workers |
| `geoip.py` | `enrich()` | Country code and ASN lookup via MaxMind GeoLite2 |
| `ip.py` | `extract_real_ip()` | Trusted-proxy-aware source-IP extraction |
| `pool.py` | `sample_chat_content()`, `sample_tool_result()`, `sample_embedding()` | Response pool sampling with `{VARIANT:a|b}` expansion |
| `streaming.py` | `openai_sse_stream()` | SSE chunk generator for streaming chat completions |
| `ratelimit.py` | `check()` | Per-IP rate limiting (soft + hard RPM thresholds) |
| `config.py` | `Settings` | Pydantic settings loaded from `/etc/inferd/inferd.env` |
| `dispatcher.py` | `route()` | Static response-pool selection helpers |

---

## Anomaly flags

`anomaly.py` produces these flags, stored in `events.anomaly_flags` as a comma-separated string:

| Flag | Triggers on |
|---|---|
| `shell_metachar` | `;`, `&&`, `\|`, backtick, `$()` in any field |
| `sql_pattern` | `SELECT`, `UNION`, `DROP`, `--` comment markers |
| `code_in_field` | `import `, `eval(`, `exec(`, `subprocess.`, `os.system` |
| `base64_payload` | Base64 string longer than 60 chars in any field |
| `path_traversal` | `../` sequences |
| `privilege_claim` | `senderIsOwner`, `isAdmin`, `role:admin` patterns |
| `command_field` | `command`, `cmd`, `action` keys with non-empty values |
| `pickle_magic` | `\x80\x04` or `gASV` pickle preamble |
| `oversized_field` | Any single field exceeding 10 KB |
| `multimodal_url` | `image_url`, `video_url`, `audio_url` keys present |
| `localhost_origin` | `Origin` or `X-Forwarded-For` containing `127.0.0.1`/`localhost` |

Flags are CVE-independent. When a new CVE is published, the flags in historical events become retroactive pre-disclosure evidence.

---

## EventRecord fields

Key fields every emulator populates:

```python
EventRecord(
    event_id          = str(uuid.uuid4()),
    session_id        = request.state.session_id,
    timestamp_us      = request.state.start_us,       # microseconds since epoch
    source_ip      = request.state.source_ip,
    service           = "openai",                     # emulator name
    endpoint          = "POST /v1/chat/completions",
    auth_key_prefix   = auth.key_prefix,              # first 7 chars, logged always
    auth_key_hash     = auth.key_hash,                # SHA-256, for lookup
    is_honeytoken     = auth.is_honeytoken,
    honeytoken_id     = auth.honeytoken_id,
    payload_json      = json.dumps(body),             # full body, never truncated
    anomaly_flags     = request.state.anomaly_flags,
    canary_echo_detected = bool(request.state.canary_echo),
    extras            = {"operation": "chat", ...},   # emulator-specific fields
)
```
