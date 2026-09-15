"""
Qdrant-compatible vector database emulator for InferD.

Port 6333, direct (no TLS).

Capture classes:
    Read ops  (GET /collections, POST .../points/search)
              → reconnaissance and enumeration behavior (H4)
    Write ops (PUT /collections/{name}, POST .../points)
              → RAG poisoning attempts - upserted content logged verbatim

The full upserted point payload is the primary research artifact for
the RAG poisoning attack class. Log every byte, never truncate.

Stateful: collection existence is tracked in SQLite so that
subsequent operations on a collection don't return 404.
"""

import json
import random
import uuid
from typing import Any

import aiosqlite
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from honeypot.core import canary as canary_mod
from honeypot.core import database, logger
from honeypot.core.logger import EventRecord, now_us

router = APIRouter()

# Fake pre-existing collections
_SEED_COLLECTIONS = [
    {"name": "documents",      "size": 4, "dim": 1536},
    {"name": "knowledge_base", "size": 12, "dim": 1536},
]


# Helpers

async def _collection_exists(name: str) -> bool:
    if any(c["name"] == name for c in _SEED_COLLECTIONS):
        return True
    conn: aiosqlite.Connection = await database.get_connection()
    async with conn.execute(
        "SELECT 1 FROM qdrant_collections WHERE collection_name = ?", (name,)
    ) as cur:
        return await cur.fetchone() is not None


async def _collection_state(name: str) -> tuple[int, int] | None:
    seed = next((c for c in _SEED_COLLECTIONS if c["name"] == name), None)
    if seed:
        return seed["size"], seed["dim"]
    conn: aiosqlite.Connection = await database.get_connection()
    async with conn.execute(
        "SELECT point_count, vector_dim FROM qdrant_collections WHERE collection_name = ?", (name,)
    ) as cur:
        row = await cur.fetchone()
    return (row[0], row[1]) if row else None


async def _log(request: Request, status: int, extras: dict) -> None:
    body = request.state.raw_body
    try:
        payload_obj = json.loads(body) if body else {}
    except Exception:
        payload_obj = {"_raw": body.decode("utf-8", errors="replace")}

    ev = EventRecord(
        event_id=str(uuid.uuid4()),
        session_id=request.state.session_id,
        timestamp_us=request.state.start_us,
        source_ip=request.state.source_ip,
        asn=request.state.geo.asn,
        asn_org=request.state.geo.asn_org,
        country_code=request.state.geo.country_code,
        service="qdrant",
        endpoint=f"{request.method} {request.url.path}",
        http_method=request.method,
        http_version=request.scope.get("http_version", ""),
        user_agent=request.headers.get("user-agent", ""),
        tls_cipher=None,
        tls_protocol=None,
        request_size_bytes=len(body),
        auth_key_prefix=None,
        auth_key_hash=None,
        is_honeytoken=False,
        honeytoken_id=None,
        payload_json=json.dumps(payload_obj, ensure_ascii=False),
        model_requested=None,
        response_status=status,
        response_time_ms=(now_us() - request.state.start_us) / 1000,
        canary_echo_detected=bool(request.state.canary_echo),
        canary_token=request.state.canary_echo,
        canary_source_session=canary_mod.lookup(request.state.canary_echo).session_id
            if request.state.canary_echo else None,
        anomaly_flags=getattr(request.state, "anomaly_flags", None),
        extras=extras,
    )
    await logger.log_event(ev)


def _fake_collection_info(name: str, size: int = 0, dim: int = 1536) -> dict:
    return {
        "result": {
            "status": "green",
            "optimizer_status": "ok",
            "vectors_count": size,
            "indexed_vectors_count": size,
            "points_count": size,
            "segments_count": 2,
            "config": {
                "params": {
                    "vectors": {"size": dim, "distance": "Cosine"},
                    "shard_number": 1,
                    "replication_factor": 1,
                    "write_consistency_factor": 1,
                    "on_disk_payload": True,
                }
            },
            "payload_schema": {},
        },
        "status": "ok",
        "time": round(random.uniform(0.001, 0.005), 6),
    }


# Routes

@router.get("/collections")
async def list_collections(request: Request):
    await _log(request, 200, {"operation": "list_collections"})
    collections = [
        {"name": c["name"], "status": "green", "vectors_count": c["size"]}
        for c in _SEED_COLLECTIONS
    ]
    conn = await database.get_connection()
    async with conn.execute("SELECT collection_name, point_count FROM qdrant_collections") as cur:
        collections.extend({"name": row[0], "status": "green", "vectors_count": row[1]}
                           for row in await cur.fetchall())
    return JSONResponse({
        "result": {"collections": collections},
        "status": "ok",
        "time": round(random.uniform(0.001, 0.003), 6),
    })


@router.get("/collections/{name}")
async def get_collection(name: str, request: Request):
    state = await _collection_state(name)
    status = 200 if state else 404
    await _log(request, status, {"operation": "get_collection", "collection": name})
    if state is None:
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)
    size, dim = state
    return JSONResponse(_fake_collection_info(name, size, dim))


@router.put("/collections/{name}")
async def create_collection(name: str, request: Request):
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    # Extract vector dimension from schema - reveals what embedding model they use.
    vectors_cfg = data.get("vectors", {})
    dim = vectors_cfg.get("size", 1536) if isinstance(vectors_cfg, dict) else 1536

    await _log(request, 200, {
        "operation": "create_collection",
        "collection": name,
        "vector_dim": dim,
        "schema_json": json.dumps(data),
    })

    await database.write_rows([{"table": "qdrant_collections", "row": {
        "collection_name": name,
        "created_at_us":   now_us(),
        "session_id":      request.state.session_id,
        "schema_json":     json.dumps(data),
        "vector_dim":      dim,
        "point_count":     0,
    }}])
    return JSONResponse({"result": True, "status": "ok",
                         "time": round(random.uniform(0.01, 0.05), 6)})


@router.delete("/collections/{name}")
async def delete_collection(name: str, request: Request):
    exists = await _collection_exists(name)
    status = 200 if exists else 404
    await _log(request, status, {"operation": "delete_collection", "collection": name})
    if not exists:
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)
    if not any(c["name"] == name for c in _SEED_COLLECTIONS):
        await database.execute("DELETE FROM qdrant_points WHERE collection_name = ?", (name,))
        await database.execute("DELETE FROM qdrant_collections WHERE collection_name = ?", (name,))
    return JSONResponse({"result": True, "status": "ok",
                         "time": round(random.uniform(0.005, 0.02), 6)})


@router.put("/collections/{name}/points")
@router.post("/collections/{name}/points")
async def upsert_points(name: str, request: Request):
    """
    RAG poisoning capture surface.
    The full payload - including any adversarially crafted text - is logged
    verbatim to both JSONL and qdrant_points table.
    """
    if not await _collection_exists(name):
        await _log(request, 404, {"operation": "upsert_points", "collection": name})
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    points = data.get("points", [])
    point_count = len(points)
    # Check if any point provides a real vector (dim signals embedding model).
    has_vector = any("vector" in p for p in points if isinstance(p, dict))
    first_vec = next(
        (p["vector"] for p in points if isinstance(p, dict) and "vector" in p), None
    )
    vector_dim = len(first_vec) if isinstance(first_vec, list) else None

    await _log(request, 200, {
        "operation":    "upsert_points",
        "collection":   name,
        "point_count":  point_count,
        "has_vector":   has_vector,
        "vector_dim":   vector_dim,
        "upsert_payload": json.dumps(data),   # Full payload - primary RAG capture.
    })

    # Store each point verbatim in qdrant_points.
    for p in points:
        if not isinstance(p, dict):
            continue
        await database.write_rows([{"table": "qdrant_points", "row": {
            "point_id":        str(p.get("id", uuid.uuid4())),
            "collection_name": name,
            "event_id":        None,
            "timestamp_us":    now_us(),
            "vector_dim":      len(p["vector"]) if isinstance(p.get("vector"), list) else None,
            "has_vector":      int("vector" in p),
            "payload_json":    json.dumps(p, ensure_ascii=False),
        }}])
    if not any(c["name"] == name for c in _SEED_COLLECTIONS):
        await database.execute(
            "UPDATE qdrant_collections SET point_count = "
            "(SELECT COUNT(*) FROM qdrant_points WHERE collection_name = ?) "
            "WHERE collection_name = ?", (name, name),
        )

    return JSONResponse({
        "result": {"operation_id": random.randint(1, 9999), "status": "completed"},
        "status": "ok",
        "time": round(random.uniform(0.002, 0.015), 6),
    })


@router.post("/collections/{name}/points/search")
async def search_points(name: str, request: Request):
    if not await _collection_exists(name):
        await _log(request, 404, {"operation": "search_points", "collection": name})
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)
    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    query_vec = data.get("vector", [])
    vector_dim = len(query_vec) if isinstance(query_vec, list) else None

    await _log(request, 200, {
        "operation":  "search_points",
        "collection": name,
        "vector_dim": vector_dim,
        "limit":      data.get("limit", 10),
        "filter":     json.dumps(data.get("filter", {})),
    })

    # Return 3 plausible fake nearest neighbours.
    hits = []
    for i in range(3):
        hits.append({
            "id":      str(uuid.uuid4()),
            "version": 1,
            "score":   round(random.uniform(0.72, 0.97), 6),
            "payload": {
                "text":   f"Relevant document excerpt {i+1}.",
                "source": f"document_{random.randint(1, 50)}.pdf",
            },
            "vector": None,
        })

    return JSONResponse({
        "result": hits,
        "status": "ok",
        "time": round(random.uniform(0.003, 0.012), 6),
    })


@router.post("/collections/{name}/points/delete")
async def delete_points(name: str, request: Request):
    if not await _collection_exists(name):
        await _log(request, 404, {"operation": "delete_points", "collection": name})
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)

    body = request.state.raw_body
    try:
        data = json.loads(body)
    except Exception:
        data = {}

    point_ids = data.get("points")
    await _log(request, 200, {
        "operation": "delete_points",
        "collection": name,
        "point_ids": json.dumps(point_ids if point_ids is not None else data.get("filter", {})),
    })

    if isinstance(point_ids, list) and not any(c["name"] == name for c in _SEED_COLLECTIONS):
        for point_id in point_ids:
            await database.execute(
                "DELETE FROM qdrant_points WHERE collection_name = ? AND point_id = ?",
                (name, str(point_id)),
            )
        await database.execute(
            "UPDATE qdrant_collections SET point_count = "
            "(SELECT COUNT(*) FROM qdrant_points WHERE collection_name = ?) "
            "WHERE collection_name = ?",
            (name, name),
        )

    return JSONResponse({
        "result": {"operation_id": random.randint(1, 9999), "status": "completed"},
        "status": "ok",
        "time": round(random.uniform(0.001, 0.008), 6),
    })


@router.get("/collections/{name}/points/{point_id}")
async def get_point(name: str, point_id: str, request: Request):
    if not await _collection_exists(name):
        await _log(request, 404, {"operation": "get_point", "collection": name, "point_id": point_id})
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)

    if any(c["name"] == name for c in _SEED_COLLECTIONS):
        await _log(request, 200, {"operation": "get_point", "collection": name, "point_id": point_id})
        return JSONResponse({
            "result": {
                "id": point_id, "version": 1,
                "payload": {"text": "Document content placeholder."},
                "vector": None,
            },
            "status": "ok",
            "time": round(random.uniform(0.001, 0.005), 6),
        })

    conn = await database.get_connection()
    async with conn.execute(
        "SELECT payload_json FROM qdrant_points WHERE collection_name = ? AND point_id = ?",
        (name, point_id),
    ) as cur:
        row = await cur.fetchone()

    status = 200 if row else 404
    await _log(request, status, {"operation": "get_point", "collection": name, "point_id": point_id})
    if row is None:
        return JSONResponse({"status": {"error": "Not found"}, "time": 0.001}, status_code=404)

    point = json.loads(row[0])
    point.setdefault("id", point_id)
    point.setdefault("version", 1)
    return JSONResponse({
        "result": point,
        "status": "ok",
        "time": round(random.uniform(0.001, 0.005), 6),
    })


@router.get("/")
async def root(request: Request):
    await _log(request, 200, {})
    return JSONResponse({
        "title": "qdrant - vector search engine",
        "version": "1.14.0",
    })
