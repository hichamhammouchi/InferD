"""
SQLite database layer for InferD.

Design:
- Single aiosqlite connection shared across the process (SQLite supports one
  writer at a time; WAL mode allows concurrent readers).
- Event/session indexing is queued through a background batch writer. Direct
  state transitions share the same per-process write lock, preventing transaction
  interleaving on the shared connection.
- JSONL append (in logger.py) is the canonical event record and happens
  synchronously before the SQLite queue put. SQLite is a structured index
  that can be rebuilt from JSONL after a database failure.
"""

import asyncio
import sys
from pathlib import Path
from typing import Any

import aiosqlite

from honeypot.core.config import settings

# Module-level state
_conn: aiosqlite.Connection | None = None
_write_queue: asyncio.Queue[dict[str, Any]] | None = None
_write_lock: asyncio.Lock | None = None

# Tables with evolving state must explicitly upsert. Event records are
# append-only and deliberately use plain INSERT so an ID collision is visible.
_CONFLICT_KEYS = {
    "sessions": "session_id",
    "threads": "thread_id",
    "mcp_sessions": "mcp_session_id",
    "canary_tokens": "token",
    "qdrant_collections": "collection_name",
    "qdrant_points": ("collection_name", "point_id"),
}


async def get_connection() -> aiosqlite.Connection:
    """Return (and lazily create) the shared aiosqlite connection."""
    global _conn
    if _conn is None:
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        _conn = await aiosqlite.connect(str(settings.db_path), timeout=5)
        await _conn.execute("PRAGMA journal_mode=WAL")
        # NORMAL sync: safe with WAL, much faster than FULL.
        await _conn.execute("PRAGMA synchronous=NORMAL")
        await _conn.execute("PRAGMA cache_size=-8000")   # 8 MB page cache
        await _conn.execute("PRAGMA temp_store=MEMORY")
        await _conn.execute("PRAGMA foreign_keys=ON")
        await _conn.execute("PRAGMA busy_timeout=5000")
    return _conn


async def _migrate_legacy_schema(conn: aiosqlite.Connection) -> None:
    """Migrate the two pre-release table layouts under one SQLite writer lock."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        async with conn.execute("PRAGMA table_info(token_registry)") as cur:
            token_cols = {row[1] for row in await cur.fetchall()}
        if token_cols and "token_format" in token_cols and "format" not in token_cols:
            await conn.execute("ALTER TABLE token_registry RENAME TO token_registry_legacy")
            await conn.execute("""
                CREATE TABLE token_registry (
                    token_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                    token_prefix TEXT NOT NULL, format TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT 'migrated', created_at_us INTEGER NOT NULL,
                    seed_location TEXT, seed_url TEXT, seed_date TEXT, notes TEXT,
                    first_use_at_us INTEGER, use_count INTEGER DEFAULT 0, revoked_at_us INTEGER
                )
            """)
            await conn.execute("""
                INSERT INTO token_registry
                    (token_id, token_hash, token_prefix, format, label, created_at_us,
                     seed_location, seed_url, seed_date, notes, first_use_at_us, use_count)
                SELECT token_id, token_hash, token_prefix, token_format, 'migrated',
                       COALESCE(first_use_at_us, CAST(strftime('%s','now') AS INTEGER) * 1000000),
                       seed_location, seed_url, seed_date, notes, first_use_at_us,
                       COALESCE(use_count, 0)
                FROM token_registry_legacy
            """)
            await conn.execute("DROP TABLE token_registry_legacy")

        async with conn.execute("PRAGMA table_info(qdrant_points)") as cur:
            qdrant_cols = await cur.fetchall()
        pk = {row[1]: row[5] for row in qdrant_cols}
        if pk.get("point_id") == 1 and pk.get("collection_name", 0) == 0:
            await conn.execute("ALTER TABLE qdrant_points RENAME TO qdrant_points_legacy")
            await conn.execute("""
                CREATE TABLE qdrant_points (
                    point_id TEXT NOT NULL, collection_name TEXT NOT NULL, event_id TEXT,
                    timestamp_us INTEGER NOT NULL, vector_dim INTEGER,
                    has_vector INTEGER DEFAULT 0, payload_json TEXT NOT NULL,
                    PRIMARY KEY (collection_name, point_id)
                )
            """)
            await conn.execute("""
                INSERT INTO qdrant_points
                    (point_id, collection_name, event_id, timestamp_us, vector_dim, has_vector, payload_json)
                SELECT point_id, collection_name, event_id, timestamp_us, vector_dim, has_vector, payload_json
                FROM qdrant_points_legacy
            """)
            await conn.execute("DROP TABLE qdrant_points_legacy")
        await conn.commit()
    except Exception:
        await conn.rollback()
        raise


async def init_db() -> None:
    """Create the schema and migrate the two pre-release table layouts."""
    schema_path = Path("/app/honeypot/db/schema.sql")
    if not schema_path.exists():
        schema_path = Path(__file__).resolve().parents[1] / "db" / "schema.sql"
    schema = schema_path.read_text()
    conn = await get_connection()
    await conn.executescript(schema)
    await _migrate_legacy_schema(conn)
    await conn.executescript(schema)
    await conn.commit()


def _get_write_queue() -> asyncio.Queue[dict[str, Any]]:
    global _write_queue
    if _write_queue is None:
        _write_queue = asyncio.Queue(maxsize=10000)
    return _write_queue


async def enqueue(table: str, row: dict[str, Any]) -> None:
    """
    Queue a row for SQLite insertion. Backpressure is intentional: silently
    discarding state updates made event/session consistency unverifiable.
    """
    if table not in {"events", *_CONFLICT_KEYS}:
        raise ValueError(f"Unsupported database table: {table}")
    await _get_write_queue().put({"table": table, "row": row.copy()})


def _statement(table: str, row: dict[str, Any]) -> tuple[str, list[Any]]:
    """Build a statement from a fixed, internal table allow-list."""
    cols = list(row)
    placeholders = ", ".join("?" for _ in cols)
    sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
    conflict_key = _CONFLICT_KEYS.get(table)
    if conflict_key:
        keys = (conflict_key,) if isinstance(conflict_key, str) else conflict_key
        updates = [col for col in cols if col not in keys]
        target = ", ".join(keys)
        if updates:
            sql += " ON CONFLICT(" + target + ") DO UPDATE SET " + ", ".join(
                f"{col} = excluded.{col}" for col in updates
            )
        else:
            sql += " ON CONFLICT(" + target + ") DO NOTHING"
    return sql, [row[col] for col in cols]


def _get_write_lock() -> asyncio.Lock:
    global _write_lock
    if _write_lock is None:
        _write_lock = asyncio.Lock()
    return _write_lock


async def write_rows(rows: list[dict[str, Any]]) -> None:
    """Write one batch with bounded retries for cross-process SQLite locks."""
    conn = await get_connection()
    async with _get_write_lock():
        for attempt in range(4):
            try:
                await conn.execute("BEGIN")
                for item in rows:
                    sql, values = _statement(item["table"], item["row"])
                    await conn.execute(sql, values)
                await conn.commit()
                return
            except asyncio.CancelledError:
                await conn.rollback()
                raise
            except Exception as exc:
                await conn.rollback()
                if "locked" not in str(exc).lower() or attempt == 3:
                    raise
                await asyncio.sleep(0.05 * (2 ** attempt))


async def execute(sql: str, values: list[Any] | tuple[Any, ...] = ()) -> None:
    """Execute a repository-owned state transition with SQLite lock retries."""
    conn = await get_connection()
    async with _get_write_lock():
        for attempt in range(4):
            try:
                await conn.execute(sql, values)
                await conn.commit()
                return
            except asyncio.CancelledError:
                await conn.rollback()
                raise
            except Exception as exc:
                await conn.rollback()
                if "locked" not in str(exc).lower() or attempt == 3:
                    raise
                await asyncio.sleep(0.05 * (2 ** attempt))


async def batch_writer() -> None:
    """
    Background coroutine: drains the write queue in batches.
    Collect up to 50 items OR wait up to 100 ms, whichever comes first,
    then write them all in a single transaction.

    Start this with asyncio.create_task() in each service's lifespan.
    """
    await get_connection()
    queue = _get_write_queue()
    batch: list[dict[str, Any]] = []

    try:
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=0.10)
                batch.append(item)
                while len(batch) < 50:
                    try:
                        batch.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
            except asyncio.TimeoutError:
                pass

            if not batch:
                continue

            try:
                await write_rows(batch)
            except Exception as exc:
                print(f"[db] batch_writer error: {exc}", file=sys.stderr)
            else:
                batch.clear()
    except asyncio.CancelledError:
        if batch:
            try:
                await write_rows(batch)
                batch.clear()
            except Exception as exc:
                print(f"[db] shutdown batch flush error: {exc}", file=sys.stderr)
        raise


async def close() -> None:
    """Graceful shutdown - flush remaining queue items then close."""
    global _conn, _write_lock, _write_queue
    if _conn is not None:
        pending: list[dict[str, Any]] = []
        queue = _write_queue
        if queue is not None:
            while True:
                try:
                    pending.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
        if pending:
            try:
                await write_rows(pending)
            except Exception as exc:
                print(f"[db] shutdown flush error: {exc}", file=sys.stderr)
        await _conn.close()
        _conn = None
    _write_lock = None
    _write_queue = None
