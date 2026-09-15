"""Release-critical regression tests for InferD's static, non-executing facade."""

import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from honeypot.core import canary, database
from honeypot.core.config import settings
from honeypot.core.pool import _load, sample_embedding


ROOT = Path(__file__).resolve().parents[1]


async def configure_db(directory: Path) -> None:
    await database.close()
    settings.db_path = directory / "honeypot.db"
    settings.raw_log_dir = directory / "raw"
    await database.init_db()


class DatabaseReleaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        await configure_db(Path(self.tmp.name))

    async def asyncTearDown(self):
        await database.close()
        self.tmp.cleanup()

    async def test_state_rows_upsert(self):
        session = {
            "session_id": "session-1", "source_ip": "198.51.100.1", "asn": None,
            "asn_org": None, "country_code": None, "first_seen_us": 1, "last_seen_us": 1,
            "service": "openai", "request_count": 1, "user_agent": "test",
            "tls_cipher": None, "tls_protocol": None, "http_version": "1.1",
            "endpoint_sequence": '["GET /one"]',
        }
        await database.write_rows([{"table": "sessions", "row": session}])
        session.update({"last_seen_us": 2, "request_count": 2,
                        "endpoint_sequence": '["GET /one", "POST /two"]'})
        await database.write_rows([{"table": "sessions", "row": session}])

        mcp = {
            "mcp_session_id": "mcp-1", "session_id": "session-1", "transport": "streamable_http",
            "created_at_us": 1, "last_seen_us": 1, "tool_calls_json": "[]", "tool_call_count": 0,
            "canary_issued": "INFERD-AAAAAA",
        }
        await database.write_rows([{"table": "mcp_sessions", "row": mcp}])
        mcp.update({"last_seen_us": 2, "tool_calls_json": '[{"seq":0},{"seq":1}]', "tool_call_count": 2})
        await database.write_rows([{"table": "mcp_sessions", "row": mcp}])

        thread = {"thread_id": "thread-1", "session_id": "session-1", "created_at_us": 1,
                  "system_prompt": None, "tools_declared": None, "messages_json": "[]",
                  "canary_issued": None, "run_count": 0}
        await database.write_rows([{"table": "threads", "row": thread}])
        thread.update({"messages_json": '[{"role":"user"}]', "run_count": 1})
        await database.write_rows([{"table": "threads", "row": thread}])

        conn = await database.get_connection()
        self.assertEqual((await (await conn.execute("SELECT request_count, last_seen_us, endpoint_sequence FROM sessions")).fetchone()),
                         (2, 2, '["GET /one", "POST /two"]'))
        self.assertEqual((await (await conn.execute("SELECT tool_call_count, tool_calls_json FROM mcp_sessions")).fetchone()),
                         (2, '[{"seq":0},{"seq":1}]'))
        self.assertEqual((await (await conn.execute("SELECT run_count, messages_json FROM threads")).fetchone()),
                         (1, '[{"role":"user"}]'))

    async def test_canary_is_persisted_and_detected_after_registry_reset(self):
        old_rate = settings.canary_injection_rate
        settings.canary_injection_rate = 1.0
        try:
            token = await canary.issue_and_persist("00000000-0000-0000-0000-000000000001", "openai", 7)
            self.assertTrue(token.startswith("INFERD-"))
            canary._registry.clear()
            self.assertEqual(await canary.scan_persisted(f"echo {token}"), token)
            record = await canary.lookup_persisted(token)
            self.assertEqual(record.service, "openai")
        finally:
            settings.canary_injection_rate = old_rate


class PoolReleaseTests(unittest.TestCase):
    def test_static_embedding_dimensions_and_normalization(self):
        for dims in (768, 1536, 3072):
            vector = sample_embedding(dims)
            self.assertEqual(len(vector), dims)
            self.assertTrue(math.isclose(sum(x * x for x in vector), 1.0, abs_tol=1e-6))
        with self.assertRaises(ValueError):
            sample_embedding(4096)

    def test_all_pool_json_parses(self):
        for path in (ROOT / "honeypot" / "response_pools").glob("*.json"):
            with self.subTest(path=path.name):
                json.loads(path.read_text())

    def test_canary_is_not_a_prompt(self):
        old_rate = settings.canary_injection_rate
        settings.canary_injection_rate = 1.0
        try:
            token = canary.issue("00000000-0000-0000-0000-000000000002", "test", 1)
            from honeypot.core.pool import sample_anthropic_content, sample_gemini_content
            self.assertIn(token, sample_anthropic_content(token))
            self.assertIn(token, sample_gemini_content(token))
        finally:
            settings.canary_injection_rate = old_rate


class TokenCliTests(unittest.TestCase):
    def test_generate_list_lookup_and_stats_on_initialized_db(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(configure_db(tmp))
            env = {**os.environ, "DB_PATH": str(tmp / "honeypot.db")}
            command = [sys.executable, "scripts/tokens.py"]
            generated = subprocess.run(command + ["generate", "--label", "release-test"], cwd=ROOT,
                                       env=env, text=True, capture_output=True, check=True)
            key = re.search(r"Key\s+: (\S+)", generated.stdout).group(1)
            self.assertIn("release-test", subprocess.run(command + ["list"], cwd=ROOT, env=env,
                                                           text=True, capture_output=True, check=True).stdout)
            self.assertIn("Token ID", subprocess.run(command + ["lookup", "--key", key], cwd=ROOT,
                                                        env=env, text=True, capture_output=True, check=True).stdout)
            self.assertIn("Tokens registered : 1", subprocess.run(command + ["stats"], cwd=ROOT,
                                                                     env=env, text=True, capture_output=True,
                                                                     check=True).stdout)
            asyncio.run(database.close())

    def test_cli_initializes_a_blank_database_from_the_canonical_schema(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            db_path = Path(raw_tmp) / "blank.db"
            env = {**os.environ, "DB_PATH": str(db_path)}
            result = subprocess.run([sys.executable, "scripts/tokens.py", "stats"], cwd=ROOT,
                                    env=env, text=True, capture_output=True, check=True)
            self.assertIn("Tokens registered : 0", result.stdout)


class ServiceImportTests(unittest.TestCase):
    def test_service_modules_import_and_expected_routes_exist(self):
        from honeypot.services import litellm_service, openai_service, qdrant_service, vllm_service
        routes = {route.path for route in litellm_service.app.routes}
        self.assertTrue({"/health", "/test/connection", "/test/tools/list"}.issubset(routes))
        self.assertIn("/collections", {route.path for route in qdrant_service.app.routes})
        self.assertIn("/v1/embeddings", {route.path for route in vllm_service.app.routes})
        self.assertIn("/v1/chat/completions", {route.path for route in openai_service.app.routes})
        self.assertIn("/chat/completions", routes)

    def test_runtime_source_contains_no_execution_sink(self):
        source = "\n".join(path.read_text() for path in (ROOT / "honeypot").rglob("*.py"))
        for forbidden in ("subprocess.", "os.system(", "eval(", "exec(", "pickle.loads(", "shell=True"):
            self.assertNotIn(forbidden, source)

    def test_middleware_records_404_and_429(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(database.close())
            settings.db_path = tmp / "honeypot.db"
            settings.raw_log_dir = tmp / "raw"
            from honeypot.services import vllm_service
            from honeypot.core import middleware, ratelimit
            old_hard, old_soft, old_latency = (
                settings.rate_limit_hard_rpm, settings.rate_limit_soft_rpm, settings.rate_limit_latency_ms
            )
            settings.rate_limit_hard_rpm, settings.rate_limit_soft_rpm, settings.rate_limit_latency_ms = 2, 2, 0
            middleware._sessions.clear()
            ratelimit._buckets.clear()
            try:
                with TestClient(vllm_service.app) as client:
                    self.assertEqual(client.get("/missing").status_code, 404)
                    self.assertEqual(client.get("/missing").status_code, 404)
                    self.assertEqual(client.get("/missing").status_code, 429)
                lines = list((tmp / "raw").glob("*.jsonl"))[0].read_text().splitlines()
                self.assertEqual({json.loads(line)["response_status"] for line in lines}, {404, 429})
            finally:
                settings.rate_limit_hard_rpm, settings.rate_limit_soft_rpm, settings.rate_limit_latency_ms = (
                    old_hard, old_soft, old_latency
                )
                asyncio.run(database.close())

    def test_real_assistants_and_mcp_state_accumulates(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(configure_db(tmp))
            key = "sk-" + "a" * 48
            import hashlib
            asyncio.run(database.write_rows([{"table": "token_registry", "row": {
                "token_id": "token-1", "token_hash": hashlib.sha256(key.encode()).hexdigest(),
                "token_prefix": key[:7], "format": "openai", "label": "test", "created_at_us": 1,
            }}]))
            asyncio.run(database.close())
            from honeypot.services import openai_service
            from honeypot.core import middleware, ratelimit
            middleware._sessions.clear()
            ratelimit._buckets.clear()
            with TestClient(openai_service.app) as client:
                headers = {"Authorization": f"Bearer {key}"}
                thread = client.post("/v1/threads", headers=headers).json()["id"]
                self.assertEqual(client.post(f"/v1/threads/{thread}/messages", headers=headers,
                                             json={"role": "user", "content": "persist me"}).status_code, 200)
                mcp_headers = {"Mcp-Session-Id": "mcp-release"}
                self.assertEqual(client.post("/mcp", headers=mcp_headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
                }).status_code, 200)
                for sequence in (2, 3):
                    self.assertEqual(client.post("/mcp", headers=mcp_headers, json={
                        "jsonrpc": "2.0", "id": sequence, "method": "tools/call",
                        "params": {"name": "execute_code", "arguments": {"code": "not run"}}
                    }).status_code, 200)
            with sqlite3.connect(tmp / "honeypot.db") as conn:
                messages, run_count = conn.execute(
                    "SELECT messages_json, run_count FROM threads WHERE thread_id = ?", (thread,)
                ).fetchone()
                tool_count, calls = conn.execute(
                    "SELECT tool_call_count, tool_calls_json FROM mcp_sessions WHERE mcp_session_id = ?",
                    ("mcp-release",),
                ).fetchone()
            self.assertIn("persist me", messages)
            self.assertEqual(run_count, 0)
            self.assertEqual(tool_count, 2)
            self.assertEqual(len(json.loads(calls)), 2)

    def test_rate_limit_uses_independent_soft_and_hard_buckets(self):
        from honeypot.core import ratelimit
        old = (settings.rate_limit_soft_rpm, settings.rate_limit_hard_rpm,
               settings.rate_limit_latency_ms)
        settings.rate_limit_soft_rpm = 2
        settings.rate_limit_hard_rpm = 4
        settings.rate_limit_latency_ms = 1
        ratelimit._buckets.clear()
        try:
            results = [asyncio.run(ratelimit.check("198.51.100.20")) for _ in range(5)]
            self.assertEqual(results[0], (True, 0.0))
            self.assertEqual(results[1], (True, 0.0))
            self.assertTrue(results[2][0] and results[2][1] > 0)
            self.assertTrue(results[3][0] and results[3][1] > 0)
            self.assertEqual(results[4], (False, 0.0))
        finally:
            (settings.rate_limit_soft_rpm, settings.rate_limit_hard_rpm,
             settings.rate_limit_latency_ms) = old
            ratelimit._buckets.clear()

    def test_revoked_honeytoken_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(configure_db(tmp))
            key = "sk-" + "r" * 48
            import hashlib
            asyncio.run(database.write_rows([{"table": "token_registry", "row": {
                "token_id": "revoked-1", "token_hash": hashlib.sha256(key.encode()).hexdigest(),
                "token_prefix": key[:7], "format": "openai", "label": "test",
                "created_at_us": 1, "revoked_at_us": 2,
            }}]))
            from honeypot.core.auth import check_honeytoken, parse_auth_header
            result = asyncio.run(check_honeytoken(parse_auth_header(f"Bearer {key}")))
            self.assertFalse(result.is_honeytoken)
            asyncio.run(database.close())


    def test_raw_authorization_key_is_not_persisted_by_default(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(database.close())
            settings.db_path = tmp / "honeypot.db"
            settings.raw_log_dir = tmp / "raw"
            old_store = settings.store_raw_auth_keys
            settings.store_raw_auth_keys = False
            from honeypot.services import litellm_service
            from honeypot.core import middleware, ratelimit
            middleware._sessions.clear()
            ratelimit._buckets.clear()
            key = "sk-" + "s" * 48
            try:
                with TestClient(litellm_service.app) as client:
                    self.assertEqual(client.get("/v1/models", headers={"Authorization": f"Bearer {key}"}).status_code, 200)
                with sqlite3.connect(tmp / "honeypot.db") as conn:
                    raw, prefix, key_hash = conn.execute(
                        "SELECT auth_key_raw, auth_key_prefix, auth_key_hash FROM events ORDER BY timestamp_us DESC LIMIT 1"
                    ).fetchone()
                self.assertIsNone(raw)
                self.assertEqual(prefix, key[:7])
                self.assertEqual(key_hash, hashlib.sha256(key.encode()).hexdigest())
                line = json.loads(next((tmp / "raw").glob("*.jsonl")).read_text().splitlines()[-1])
                self.assertIsNone(line["auth_key_raw"])
            finally:
                settings.store_raw_auth_keys = old_store
                asyncio.run(database.close())

    def test_request_body_limit_returns_413_and_logs_once(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(database.close())
            settings.db_path = tmp / "honeypot.db"
            settings.raw_log_dir = tmp / "raw"
            old_limit = settings.max_request_body_bytes
            settings.max_request_body_bytes = 32
            from honeypot.services import litellm_service
            from honeypot.core import middleware, ratelimit
            middleware._sessions.clear()
            ratelimit._buckets.clear()
            try:
                with TestClient(litellm_service.app) as client:
                    response = client.post("/test/connection", json={"command": "x" * 128})
                    self.assertEqual(response.status_code, 413)
                lines = next((tmp / "raw").glob("*.jsonl")).read_text().splitlines()
                self.assertEqual(len(lines), 1)
                self.assertEqual(json.loads(lines[0])["response_status"], 413)
            finally:
                settings.max_request_body_bytes = old_limit
                asyncio.run(database.close())

    def test_handler_404_is_not_double_logged(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(database.close())
            settings.db_path = tmp / "honeypot.db"
            settings.raw_log_dir = tmp / "raw"
            from honeypot.services import qdrant_service
            from honeypot.core import middleware, ratelimit
            middleware._sessions.clear()
            ratelimit._buckets.clear()
            with TestClient(qdrant_service.app) as client:
                self.assertEqual(client.get("/collections/does-not-exist").status_code, 404)
            lines = next((tmp / "raw").glob("*.jsonl")).read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["response_status"], 404)
            asyncio.run(database.close())

    def test_supervisor_keeps_cloud_backend_loopback_only(self):
        config = (ROOT / "supervisord.conf").read_text()
        openai_block = config.split("[program:openai]", 1)[1].split("[program:ollama]", 1)[0]
        self.assertIn("--host 127.0.0.1", openai_block)
        openclaw_block = config.split("[program:openclaw]", 1)[1]
        self.assertIn("--ws-max-size 33554432", openclaw_block)

    def test_direct_source_ip_ignores_untrusted_x_real_ip(self):
        from types import SimpleNamespace
        from honeypot.core.ip import extract_real_ip
        direct = SimpleNamespace(client=SimpleNamespace(host="198.51.100.9"),
                                 headers={"x-real-ip": "203.0.113.99"})
        proxied = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                                  headers={"x-real-ip": "203.0.113.99"})
        self.assertEqual(extract_real_ip(direct), "198.51.100.9")
        self.assertEqual(extract_real_ip(proxied), "203.0.113.99")

    def test_major_service_health_aliases_and_qdrant_lifecycle(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            asyncio.run(database.close())
            settings.db_path = tmp / "honeypot.db"
            settings.raw_log_dir = tmp / "raw"
            from honeypot.services import litellm_service, qdrant_service, vllm_service
            from honeypot.core import middleware, ratelimit
            middleware._sessions.clear()
            ratelimit._buckets.clear()
            with TestClient(vllm_service.app) as client:
                self.assertEqual(client.get("/health").status_code, 200)
            with TestClient(litellm_service.app) as client:
                self.assertEqual(client.get("/health").status_code, 200)
                self.assertEqual(client.post("/test/connection", json={"command": "ignored"}).status_code, 200)
                self.assertEqual(client.post("/test/tools/list", json={"command": "ignored"}).status_code, 200)
            with TestClient(qdrant_service.app) as client:
                self.assertEqual(client.get("/collections/release-test").status_code, 404)
                self.assertEqual(client.put("/collections/release-test", json={"vectors": {"size": 3}}).status_code, 200)
                self.assertEqual(client.post("/collections/release-test/points", json={
                    "points": [{"id": "point-1", "vector": [0.1, 0.2, 0.3], "payload": {"x": "y"}}]
                }).status_code, 200)
                info = client.get("/collections/release-test").json()
                self.assertEqual(info["result"]["points_count"], 1)
                point = client.get("/collections/release-test/points/point-1")
                self.assertEqual(point.status_code, 200)
                self.assertEqual(point.json()["result"]["payload"], {"x": "y"})
                self.assertEqual(client.post("/collections/release-test/points/delete",
                                             json={"points": ["point-1"]}).status_code, 200)
                self.assertEqual(client.get("/collections/release-test/points/point-1").status_code, 404)
                self.assertEqual(client.delete("/collections/release-test").status_code, 200)
                self.assertEqual(client.get("/collections/release-test").status_code, 404)
            asyncio.run(database.close())
