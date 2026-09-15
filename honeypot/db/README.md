# db/

SQLite schema for InferD. The schema is applied at container startup by `core/database.py` using `IF NOT EXISTS`, safe to run repeatedly.

Database file on the server: `/data/db/honeypot.db` (WAL mode, bind-mounted from host).

---

## Tables

| Table | One row per | Key research use |
|---|---|---|
| `events` | HTTP request | Core metadata, payload, auth, anomaly flags, canary echo |
| `sessions` | (source_ip, 30-min inactivity window) | Session-level behavioural fingerprint, endpoint sequence |
| `mcp_sessions` | MCP session ID | Full tool-call sequence across multiple JSON-RPC requests |
| `threads` | Assistants API thread | System prompt, tool definitions, full message history |
| `canary_tokens` | Issued canary token | Tracks issue → echo, confirms LLM-mediated output processing |
| `token_registry` | Honeytoken | Seeding metadata (where/when planted), first use, use count |
| `cve_candidates` | CVE ID | Signatures, probe counts, first-seen timestamps |
| `qdrant_collections` | Collection name | Stateful emulation of Qdrant collection lifecycle |
| `qdrant_points` | Upserted point | Serialized point object for RAG poisoning research |

---

## Key fields in `events`

```
timestamp_us        INTEGER   microseconds since epoch (NOT milliseconds)
service             TEXT      'ollama' | 'openai' | 'mcp' | 'openclaw' | ...
endpoint            TEXT      'POST /v1/chat/completions'
payload_json        TEXT      full request body, never truncated
auth_key_prefix     TEXT      first 7 chars of the key (logged even on 401)
auth_key_hash       TEXT      SHA-256 hex (for honeytoken lookup)
auth_key_raw        TEXT      NULL by default; populated only when STORE_RAW_AUTH_KEYS=true
is_honeytoken       INTEGER   1 if matched a seeded key
anomaly_flags       TEXT      comma-separated: 'shell_metachar,pickle_magic,...'
canary_echo_detected INTEGER  1 if the request body contained a previously issued canary
emulator extras     JSONL only  Emulator-specific fields are retained in the canonical JSONL record
```

---

## Useful queries

```sql
-- Event volume by service
SELECT service, COUNT(*) n FROM events GROUP BY service ORDER BY n DESC;

-- Hourly probe rate (last 24h)
SELECT strftime('%H:00', timestamp_us/1e6, 'unixepoch') hour, COUNT(*) n
FROM events WHERE timestamp_us > (strftime('%s','now') - 86400) * 1e6
GROUP BY hour ORDER BY hour;

-- All honeytoken hits with key prefix and IP
SELECT datetime(timestamp_us/1e6,'unixepoch'), service, auth_key_prefix, source_ip
FROM events WHERE is_honeytoken = 1 ORDER BY timestamp_us DESC;

-- MCP tool-call arguments are retained in the canonical JSONL record. Query
-- them with the offline JSONL analysis pipeline; SQLite stores shared event fields.

-- RAG poisoning attempts (Qdrant upserts)
SELECT collection_name, payload_json, timestamp_us/1e6 ts
FROM qdrant_points ORDER BY timestamp_us DESC LIMIT 20;

-- Anomaly flag breakdown
SELECT trim(value) flag, COUNT(*) n
FROM events, json_each('["' || replace(anomaly_flags,',','","') || '"]')
WHERE anomaly_flags != '' GROUP BY flag ORDER BY n DESC;

-- IPs that echoed a canary (LLM-mediated processing confirmed)
SELECT c.token, c.service, e.source_ip, e.user_agent
FROM canary_tokens c JOIN events e ON e.event_id = c.echo_event_id
WHERE c.echo_detected_at_us IS NOT NULL;
```

---

## Schema file

Full DDL: [`schema.sql`](schema.sql), all `CREATE TABLE IF NOT EXISTS` + indexes optimized for time-range scans, per-service aggregates, honeytoken lookups, and canary echo detection.
