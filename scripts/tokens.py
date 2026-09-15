#!/usr/bin/env python3
"""
InferD - Honeytoken CLI

Manage honeytoken API keys that trigger full-response capture and canary
injection when used against InferD endpoints.

Commands:
    generate  Create and register a new honeytoken key
    list      List all registered tokens with hit statistics
    lookup    Look up a token by raw key value or token_id
    revoke    Mark a token as revoked (still logged if used)
    stats     Show aggregate honeytoken hit statistics

Usage:
    python3 scripts/tokens.py generate --format openai --label "pentest-lab"
    python3 scripts/tokens.py list
    python3 scripts/tokens.py lookup --key sk-...
    python3 scripts/tokens.py stats

Key formats generated (no honeypot marker, so a stolen key looks real):
    openai     sk-<48 alnum>
    anthropic  sk-ant-api03-<48 alnum>
    gemini     AIza<35 alnum>
    generic    sk-<48 alnum>
"""

import argparse
import hashlib
import os
import secrets
import sqlite3
import string
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Paths
DB_PATH = Path(os.environ.get("DB_PATH", "/data/db/honeypot.db"))

# For local development, fall back to a local path
if not DB_PATH.parent.exists():
    DB_PATH = Path(__file__).parent.parent / "data" / "honeypot.db"
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


# Key generation

def _random_alnum(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def generate_key(fmt: str) -> str:
    """Generate a honeytoken key in the given format."""
    if fmt == "openai":
        return f"sk-{_random_alnum(48)}"
    elif fmt == "anthropic":
        return f"sk-ant-api03-{_random_alnum(48)}"
    elif fmt == "gemini":
        return f"AIza{_random_alnum(35)}"
    else:
        return f"sk-{_random_alnum(48)}"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# Database helpers

def get_conn() -> sqlite3.Connection:
    """Open the canonical honeypot database, creating its parent if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=5)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def ensure_table(conn: sqlite3.Connection) -> None:
    """Apply the canonical schema and migrate the pre-release token table."""
    schema_path = Path(__file__).resolve().parent.parent / "honeypot" / "db" / "schema.sql"
    schema = schema_path.read_text()
    conn.executescript(schema)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(token_registry)")}
    if columns and "token_format" in columns and "format" not in columns:
        conn.execute("ALTER TABLE token_registry RENAME TO token_registry_legacy")
        conn.execute("""
            CREATE TABLE token_registry (
                token_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                token_prefix TEXT NOT NULL, format TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT 'migrated', created_at_us INTEGER NOT NULL,
                seed_location TEXT, seed_url TEXT, seed_date TEXT, notes TEXT,
                first_use_at_us INTEGER, use_count INTEGER DEFAULT 0, revoked_at_us INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO token_registry
                (token_id, token_hash, token_prefix, format, label, created_at_us,
                 seed_location, seed_url, seed_date, notes, first_use_at_us, use_count)
            SELECT token_id, token_hash, token_prefix, token_format, 'migrated',
                   COALESCE(first_use_at_us, CAST(strftime('%s','now') AS INTEGER) * 1000000),
                   seed_location, seed_url, seed_date, notes, first_use_at_us, COALESCE(use_count, 0)
            FROM token_registry_legacy
        """)
        conn.execute("DROP TABLE token_registry_legacy")
        conn.executescript(schema)
    conn.commit()


# Commands

def cmd_generate(args: argparse.Namespace) -> None:
    key = generate_key(args.format)
    key_hash = hash_key(key)
    token_id = str(uuid.uuid4())
    now_us = int(datetime.now(timezone.utc).timestamp() * 1000000)

    conn = get_conn()
    ensure_table(conn)
    conn.execute("""
        INSERT INTO token_registry
            (token_id, token_hash, token_prefix, label, format, created_at_us,
             seed_location, seed_url, seed_date, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (token_id, key_hash, key[:7], args.label, args.format, now_us,
          args.seed_location, args.seed_url, args.seed_date, args.notes))
    conn.commit()
    conn.close()

    print(f"\n  Token ID : {token_id}")
    print(f"  Format   : {args.format}")
    print(f"  Label    : {args.label}")
    print(f"  Key      : {key}")
    print()
    print("  Seed this key only in a controlled decoy location covered by your research protocol,")
    print("  for example a honeypot-owned fake .env or configuration file.")
    print()
    print("  When the key is used against InferD, it will:")
    print("    - Receive a full AI-like response (not a 401)")
    print("    - Trigger canary token injection")
    print("    - Log all request content verbatim")
    print()


def cmd_list(args: argparse.Namespace) -> None:
    conn = get_conn()
    ensure_table(conn)
    rows = conn.execute("""
        SELECT token_id, label, format, created_at_us,
               use_count, first_use_at_us, revoked_at_us
        FROM token_registry
        ORDER BY created_at_us DESC
    """).fetchall()
    conn.close()

    if not rows:
        print("No tokens registered.")
        return

    def fmt_us(ts_us):
        if ts_us is None:
            return "-"
        return datetime.fromtimestamp(ts_us / 1000000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"\n  {'ID':36s}  {'Label':20s}  {'Format':9s}  {'Hits':5s}  {'Created':17s}  {'First Hit':17s}  Status")
    print("  " + "-" * 120)
    for row in rows:
        status = "REVOKED" if row["revoked_at_us"] else ("HIT" if row["use_count"] > 0 else "active")
        print(
            f"  {row['token_id']:36s}  "
            f"{row['label']:20s}  "
            f"{row['format']:9s}  "
            f"{row['use_count']:5d}  "
            f"{fmt_us(row['created_at_us']):17s}  "
            f"{fmt_us(row['first_use_at_us']):17s}  "
            f"{status}"
        )
    print()


def cmd_lookup(args: argparse.Namespace) -> None:
    conn = get_conn()
    ensure_table(conn)

    if args.key:
        key_hash = hash_key(args.key)
        row = conn.execute(
            "SELECT * FROM token_registry WHERE token_hash = ?", (key_hash,)
        ).fetchone()
    elif args.id:
        row = conn.execute(
            "SELECT * FROM token_registry WHERE token_id = ?", (args.id,)
        ).fetchone()
    else:
        sys.exit("Provide --key or --id")

    if row is None:
        print("Token not found.")
        conn.close()
        return

    def fmt_us(ts_us):
        if ts_us is None:
            return "-"
        return datetime.fromtimestamp(ts_us / 1000000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print()
    print(f"  Token ID        : {row['token_id']}")
    print(f"  Label           : {row['label']}")
    print(f"  Format          : {row['format']}")
    print(f"  Key hash (sha256): {row['token_hash']}")
    print(f"  Created         : {fmt_us(row['created_at_us'])}")
    print(f"  Use count       : {row['use_count']}")
    print(f"  First use       : {fmt_us(row['first_use_at_us'])}")
    print(f"  Revoked         : {fmt_us(row['revoked_at_us'])}")
    if row['notes']:
        print(f"  Notes           : {row['notes']}")

    # Recent events using this token
    events = conn.execute("""
        SELECT timestamp_us, source_ip, country_code, asn_org,
               service, endpoint, response_status
        FROM events
        WHERE is_honeytoken = 1
          AND auth_key_hash = ?
        ORDER BY timestamp_us DESC
        LIMIT 10
    """, (row['token_hash'],)).fetchall()

    if events:
        print(f"\n  Recent uses ({len(events)} shown):")
        print(f"  {'Timestamp':24s}  {'Source IP':18s}  {'CC':3s}  {'ASN Org':24s}  {'Service':12s}  Status")
        print("  " + "-" * 100)
        for ev in events:
            ts_str = datetime.fromtimestamp(
                ev['timestamp_us'] / 1000000, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(
                f"  {ts_str:24s}  "
                f"{(ev['source_ip'] or '?'):18s}  "
                f"{(ev['country_code'] or '??'):3s}  "
                f"{(ev['asn_org'] or '?')[:24]:24s}  "
                f"{(ev['service'] or '?'):12s}  "
                f"{ev['response_status']}"
            )
    print()
    conn.close()


def cmd_revoke(args: argparse.Namespace) -> None:
    conn = get_conn()
    ensure_table(conn)
    now_us = int(datetime.now(timezone.utc).timestamp() * 1000000)

    if args.key:
        key_hash = hash_key(args.key)
        n = conn.execute(
            "UPDATE token_registry SET revoked_at_us = ? WHERE token_hash = ?",
            (now_us, key_hash)
        ).rowcount
    elif args.id:
        n = conn.execute(
            "UPDATE token_registry SET revoked_at_us = ? WHERE token_id = ?",
            (now_us, args.id)
        ).rowcount
    else:
        sys.exit("Provide --key or --id")

    conn.commit()
    conn.close()

    if n:
        print("Token revoked. It will still be logged if used, but will return 401.")
    else:
        print("Token not found.")


def cmd_stats(args: argparse.Namespace) -> None:
    conn = get_conn()
    ensure_table(conn)

    total   = conn.execute("SELECT COUNT(*) FROM token_registry").fetchone()[0]
    active  = conn.execute("SELECT COUNT(*) FROM token_registry WHERE revoked_at_us IS NULL").fetchone()[0]
    hit     = conn.execute("SELECT COUNT(*) FROM token_registry WHERE use_count > 0").fetchone()[0]
    total_uses = conn.execute("SELECT SUM(use_count) FROM token_registry").fetchone()[0] or 0

    print(f"\n  Tokens registered : {total}")
    print(f"  Active            : {active}")
    print(f"  Ever triggered    : {hit}")
    print(f"  Total uses        : {total_uses}")

    # Events with honeytokens
    ev_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE is_honeytoken = 1"
    ).fetchone()[0]
    canary_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE is_honeytoken = 1 AND canary_echo_detected = 1"
    ).fetchone()[0]
    print(f"\n  Events via token  : {ev_count}")
    print(f"  Canary echoes     : {canary_count}")

    # Top countries for honeytoken use
    print("\n  Top countries (honeytoken use):")
    rows = conn.execute("""
        SELECT country_code, COUNT(*) AS n
        FROM events WHERE is_honeytoken = 1 AND country_code IS NOT NULL
        GROUP BY country_code ORDER BY n DESC LIMIT 10
    """).fetchall()
    for row in rows:
        print(f"    {row[0]:4s}  {row[1]}")

    print()
    conn.close()


# CLI entry point

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tokens.py",
        description="InferD honeytoken management CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate
    p_gen = sub.add_parser("generate", help="Create and register a new honeytoken key")
    p_gen.add_argument("--format", choices=["openai", "anthropic", "gemini", "generic"],
                       default="openai", help="Key format (default: openai)")
    p_gen.add_argument("--label", default="unnamed", help="Human-readable label")
    p_gen.add_argument("--seed-location", help="Optional controlled seed location")
    p_gen.add_argument("--seed-url", help="Optional controlled seed URL")
    p_gen.add_argument("--seed-date", help="Optional ISO-8601 seed date")
    p_gen.add_argument("--notes", help="Optional operator notes")
    p_gen.set_defaults(func=cmd_generate)

    # list
    p_list = sub.add_parser("list", help="List all registered tokens")
    p_list.set_defaults(func=cmd_list)

    # lookup
    p_lookup = sub.add_parser("lookup", help="Look up a token by key or ID")
    g = p_lookup.add_mutually_exclusive_group()
    g.add_argument("--key", help="Raw key value")
    g.add_argument("--id",  help="Token UUID")
    p_lookup.set_defaults(func=cmd_lookup)

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke a token")
    g2 = p_revoke.add_mutually_exclusive_group()
    g2.add_argument("--key", help="Raw key value")
    g2.add_argument("--id",  help="Token UUID")
    p_revoke.set_defaults(func=cmd_revoke)

    # stats
    p_stats = sub.add_parser("stats", help="Aggregate statistics")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
