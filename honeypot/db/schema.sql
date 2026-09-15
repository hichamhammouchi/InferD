-- InferD SQLite schema
-- All CREATE statements use IF NOT EXISTS - safe to run repeatedly.
-- WAL mode and pragmas are set by database.py at connection time.

-- ====
-- SESSIONS
-- One row per (source_ip, 30-minute inactivity window).
-- Updated on every event from this IP within the window.
-- ====
CREATE TABLE IF NOT EXISTS sessions (
    session_id          TEXT PRIMARY KEY,
    source_ip           TEXT NOT NULL,
    asn                 INTEGER,
    asn_org             TEXT,
    country_code        TEXT,
    first_seen_us       INTEGER NOT NULL,
    last_seen_us        INTEGER,
    service             TEXT NOT NULL,          -- first service contacted
    request_count       INTEGER DEFAULT 1,
    user_agent          TEXT,
    tls_cipher          TEXT,
    tls_protocol        TEXT,
    http_version        TEXT,
    endpoint_sequence   TEXT,                  -- JSON array, updated per event
    has_auth_header     INTEGER DEFAULT 0,
    has_system_prompt   INTEGER DEFAULT 0,
    has_tool_calls      INTEGER DEFAULT 0,
    canary_confirmed    INTEGER DEFAULT 0
);

-- ====
-- EVENTS
-- One row per HTTP request across all services.
-- payload_json stores the full request body - never truncated.
-- ====
CREATE TABLE IF NOT EXISTS events (
    event_id            TEXT PRIMARY KEY,
    session_id          TEXT REFERENCES sessions(session_id),
    timestamp_us        INTEGER NOT NULL,
    source_ip           TEXT NOT NULL,
    asn                 INTEGER,
    asn_org             TEXT,
    country_code        TEXT,
    service             TEXT NOT NULL,
    endpoint            TEXT NOT NULL,
    http_method         TEXT,
    http_version        TEXT,
    user_agent          TEXT,
    tls_cipher          TEXT,
    tls_protocol        TEXT,
    request_size_bytes  INTEGER,
    auth_key_prefix     TEXT,
    auth_key_hash       TEXT,
    auth_key_raw        TEXT,
    is_honeytoken       INTEGER DEFAULT 0,
    honeytoken_id       TEXT,
    model_requested     TEXT,
    payload_json        TEXT,
    response_status     INTEGER,
    response_time_ms    REAL,
    canary_echo_detected INTEGER DEFAULT 0,
    canary_token        TEXT,
    canary_source_session TEXT,
    anomaly_flags       TEXT                   -- comma-separated structural anomaly signals
);

-- ====
-- CVE CANDIDATES
-- Populated by an out-of-band CVE feed (not included in this artifact).
-- Signatures derived manually and stored here for retroactive analysis.
-- ====
CREATE TABLE IF NOT EXISTS cve_candidates (
    cve_id              TEXT PRIMARY KEY,
    product             TEXT NOT NULL,
    cvss                REAL,
    published_date      TEXT,
    summary             TEXT,
    status              TEXT DEFAULT 'needs_review',
                        -- needs_review | not_relevant | has_signature | scanned
    -- Signature fields (filled in manually after reading the CVE)
    sig_endpoint        TEXT,   -- e.g. "POST /v1/completions"
    sig_field           TEXT,   -- e.g. "prompt_embeds"
    sig_pattern         TEXT,   -- e.g. "base64" or exact string
    sig_port            INTEGER,-- which honeypot service port
    sig_notes           TEXT,   -- human notes on the exploit mechanism
    -- Analysis output (filled by an offline analysis step, not included).
    first_seen_us       INTEGER,-- timestamp of earliest matching event
    probe_count         INTEGER DEFAULT 0,
    last_scanned_us     INTEGER,
    added_us            INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000)
);

-- ====
-- ASSISTANTS API THREADS
-- Stateful across multiple requests (create_assistant → add_message → run).
-- messages_json is appended on each POST /v1/threads/{id}/messages.
-- ====
CREATE TABLE IF NOT EXISTS threads (
    thread_id           TEXT PRIMARY KEY,
    session_id          TEXT,
    created_at_us       INTEGER,
    system_prompt       TEXT,          -- from POST /v1/assistants body
    tools_declared      TEXT,          -- JSON array of tool definitions
    messages_json       TEXT,          -- full message history, appended
    canary_issued       TEXT,          -- canary token embedded in responses
    run_count           INTEGER DEFAULT 0,
    last_event_id       TEXT
);

-- ====
-- MCP SESSIONS
-- Stateful across tool/list + tool/call sequences.
-- tool_calls_json: JSON array of {tool, args, timestamp_us, seq}.
-- ====
CREATE TABLE IF NOT EXISTS mcp_sessions (
    mcp_session_id      TEXT PRIMARY KEY,      -- from Mcp-Session-Id header
    session_id          TEXT,
    transport           TEXT,                  -- 'sse' | 'streamable_http'
    created_at_us       INTEGER,
    last_seen_us        INTEGER,
    tool_calls_json     TEXT,
    tool_call_count     INTEGER DEFAULT 0,
    canary_issued       TEXT
);

-- ====
-- CANARY TOKENS
-- Per-session tokens embedded in responses; tracked until echo confirmed.
-- ====
CREATE TABLE IF NOT EXISTS canary_tokens (
    token               TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    service             TEXT NOT NULL,
    issued_at_us        INTEGER NOT NULL,
    echo_detected_at_us INTEGER,          -- NULL until confirmed
    echo_event_id       TEXT,
    echo_session_id     TEXT              -- may differ from issuing session
);

-- ====
-- HONEYTOKEN REGISTRY
-- Managed by scripts/tokens.py.
-- token_hash is used for lookup (never store the full raw token).
-- ====
CREATE TABLE IF NOT EXISTS token_registry (
    token_id            TEXT PRIMARY KEY,
    token_hash          TEXT UNIQUE NOT NULL,  -- SHA-256 hex
    token_prefix        TEXT NOT NULL,         -- first 7 chars
    format              TEXT NOT NULL,         -- 'openai' | 'anthropic' | 'gemini' | 'generic'
    label               TEXT NOT NULL DEFAULT 'unnamed',
    created_at_us       INTEGER NOT NULL,
    seed_location       TEXT,                  -- optional provenance metadata
    seed_url            TEXT,
    seed_date           TEXT,                  -- ISO 8601
    notes               TEXT,
    first_use_at_us     INTEGER,
    use_count           INTEGER DEFAULT 0,
    revoked_at_us       INTEGER
);

-- ====
-- QDRANT EMULATION STATE
-- Tracks which collections have been created for stateful emulation.
-- ====
CREATE TABLE IF NOT EXISTS qdrant_collections (
    collection_name     TEXT PRIMARY KEY,
    created_at_us       INTEGER,
    session_id          TEXT,
    schema_json         TEXT,
    vector_dim          INTEGER,
    point_count         INTEGER DEFAULT 0
);

-- Every upserted point - verbatim payload, for RAG poisoning research.
CREATE TABLE IF NOT EXISTS qdrant_points (
    point_id            TEXT NOT NULL,
    collection_name     TEXT NOT NULL,
    event_id            TEXT,
    timestamp_us        INTEGER NOT NULL,
    vector_dim          INTEGER,
    has_vector          INTEGER DEFAULT 0,
    payload_json        TEXT NOT NULL,
    PRIMARY KEY (collection_name, point_id)
);

-- ====
-- INDEXES
-- Optimised for the queries the research pipeline and dashboard export
-- will actually run: time-range scans, per-service aggregates, IP lookups,
-- honeytoken hits, canary echo detection.
-- ====
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(timestamp_us);

CREATE INDEX IF NOT EXISTS idx_events_service
    ON events(service);

CREATE INDEX IF NOT EXISTS idx_events_endpoint
    ON events(endpoint);

CREATE INDEX IF NOT EXISTS idx_events_auth_hash
    ON events(auth_key_hash);

CREATE INDEX IF NOT EXISTS idx_events_source
    ON events(source_ip);

CREATE INDEX IF NOT EXISTS idx_events_country
    ON events(country_code);

CREATE INDEX IF NOT EXISTS idx_events_honeytoken
    ON events(is_honeytoken)
    WHERE is_honeytoken = 1;

CREATE INDEX IF NOT EXISTS idx_events_canary
    ON events(canary_echo_detected)
    WHERE canary_echo_detected = 1;

CREATE INDEX IF NOT EXISTS idx_sessions_source
    ON sessions(source_ip);

CREATE INDEX IF NOT EXISTS idx_sessions_first_seen
    ON sessions(first_seen_us);

CREATE INDEX IF NOT EXISTS idx_sessions_country
    ON sessions(country_code);

CREATE INDEX IF NOT EXISTS idx_sessions_asn
    ON sessions(asn);

CREATE INDEX IF NOT EXISTS idx_canary_token
    ON canary_tokens(token);

CREATE INDEX IF NOT EXISTS idx_qdrant_points_coll
    ON qdrant_points(collection_name);

CREATE INDEX IF NOT EXISTS idx_token_registry_hash
    ON token_registry(token_hash);
