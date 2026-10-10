import os
import sys
import threading
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load project .env once so every entrypoint (orchestrator, train, tui)
# picks up PG* without relying on caller to call load_dotenv first.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


    # Connect to PostgreSQL with env-based credentials, falling back to defaults.
def get_connection():
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=int(os.environ.get("PGPORT", "5432")),
        database=os.environ.get("PGDATABASE", "network_logs"),
        user=os.environ.get("PGUSER", "monitor"),
        password=os.environ.get("PGPASSWORD", "monitor"),
        connect_timeout=int(os.environ.get("PGCONNECT_TIMEOUT", "3")),
        options="-c search_path=public -c statement_timeout=10000"
    )


def get_connection_retry(stop_event=None, attempts=10):
    """Bounded startup retry; shutdown interrupts the backoff."""
    stop_event = stop_event or threading.Event()
    for attempt in range(attempts):
        if stop_event.is_set():
            return None
        try:
            conn = get_connection()
            ensure_runtime_schema(conn)
            return conn
        except psycopg2.OperationalError:
            if attempt == attempts - 1:
                raise
            print("[DB] Waiting for PostgreSQL...", file=sys.stderr)
            if stop_event.wait(min(attempt + 1, 5)):
                return None


def ensure_runtime_schema(conn):
    """Create runtime tables when connecting to a pre-migration volume."""
    with conn.cursor() as cursor:
        # Ingest and detector can connect concurrently on first startup.
        # Serialize CREATE TABLE so PostgreSQL does not race while creating
        # the table's implicit composite type.
        cursor.execute("SELECT pg_advisory_xact_lock(81726391)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_cooldowns (
                signature TEXT PRIMARY KEY,
                anomaly_id INTEGER NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
                repeat_count INTEGER NOT NULL DEFAULT 1 CHECK (repeat_count > 0),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_cooldowns_last_seen ON detection_cooldowns (last_seen)")
    conn.commit()


def prune_history(cursor):
    """Hourly retention; zero days explicitly disables a table's retention."""
    for table, variable, default in (("logs", "LOG_RETENTION_DAYS", "7"),
                                     ("anomalies", "ANOMALY_RETENTION_DAYS", "30")):
        days = int(os.environ.get(variable, default))
        if days < 0:
            raise ValueError(f"{variable} must be nonnegative")
        if days:
            cursor.execute(f"DELETE FROM {table} WHERE timestamp < NOW() - make_interval(days => %s)", (days,))
    cursor.execute("DELETE FROM detection_cooldowns WHERE last_seen < NOW() - INTERVAL '1 day'")


def cooldown_signature(hit):
    return f"{hit.get('type', '?')}|{hit.get('entity') or hit.get('src_ip') or '-'}"


def get_cooldown(cursor, signature):
    cursor.execute(
        "SELECT anomaly_id, repeat_count, EXTRACT(EPOCH FROM (NOW() - last_seen)) "
        "FROM detection_cooldowns WHERE signature = %s",
        (signature,),
    )
    row = cursor.fetchone()
    return row if row else None


def save_cooldown(cursor, signature, anomaly_id, repeat_count):
    cursor.execute(
        "INSERT INTO detection_cooldowns (signature, anomaly_id, repeat_count, last_seen) "
        "VALUES (%s, %s, %s, NOW()) "
        "ON CONFLICT (signature) DO UPDATE SET anomaly_id = EXCLUDED.anomaly_id, "
        "repeat_count = EXCLUDED.repeat_count, last_seen = NOW()",
        (signature, anomaly_id, repeat_count),
    )


LOG_COLUMNS = (
    "timestamp", "hostname", "facility", "severity",
    "device_type", "event", "src_ip", "dst_ip", "proto", "dst_port",
    # Detail fields; absent keys insert as NULL via .get()
    "src_port", "action",
    "mac", "vlan_id", "ifname", "peer_ifname", "stp_root",
    "client_mac", "ssid", "radio", "reason", "signal_dbm",
    "tx_rate_mbps", "eap_status",
    "ospf_nbr", "gateway", "route_dst", "dhcp_mac", "conntrack_count",
    "raw_line",
)

_LOG_COLS_SQL = ", ".join(LOG_COLUMNS)
_LOG_PLACEHOLDERS = ", ".join(["%s"] * len(LOG_COLUMNS))


def _entry_tuple(entry):
    return tuple(entry.get(col) for col in LOG_COLUMNS)


def insert_log_entry(cursor, entry):
    cursor.execute(
        f"INSERT INTO logs ({_LOG_COLS_SQL}) VALUES ({_LOG_PLACEHOLDERS})",
        _entry_tuple(entry),
    )


def insert_log_batch(cursor, entries):
    entries = list(entries)
    if not entries:
        return
    if len(entries) == 1:
        insert_log_entry(cursor, entries[0])
        return
    execute_values(
        cursor,
        f"INSERT INTO logs ({_LOG_COLS_SQL}) VALUES %s",
        [_entry_tuple(e) for e in entries],
    )


    # Query logs from the last N seconds.
def query_window(cursor, window_seconds=60):
    cursor.execute(
        f"""SELECT {_LOG_COLS_SQL}
        FROM logs
        WHERE timestamp >= NOW() - make_interval(secs => %s)
          AND timestamp <= NOW()
        ORDER BY timestamp""",
        (window_seconds,),
    )

    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


    # Insert a detected anomaly. Returns the new row id.
def insert_anomaly(cursor, anomaly, window_seconds=30):
    cursor.execute("""
        INSERT INTO anomalies (timestamp, window_start, window_end,
                               anomaly_score, features, severity, description)
        VALUES (NOW(), NOW() - make_interval(secs => %s), NOW(),
                %s, %s::jsonb, %s, %s)
        RETURNING id
    """, (
        window_seconds,
        anomaly["anomaly_score"],
        anomaly["features"],
        anomaly["severity"],
        anomaly["description"],
    ))
    return cursor.fetchone()[0]


    # Merge a repeat detection into an existing anomaly row.
def bump_anomaly(cursor, anomaly_id, repeat_count):
    cursor.execute("""
        UPDATE anomalies
        SET window_end = NOW(),
            features = COALESCE(features, '{}'::jsonb)
                       || jsonb_build_object(
                              'repeat_count', %s::int,
                              'last_seen', NOW()::text)
        WHERE id = %s
    """, (repeat_count, anomaly_id))
