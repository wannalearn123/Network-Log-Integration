import os

import psycopg2
from psycopg2.extras import execute_values


    # Connect to PostgreSQL database.
    #
    # Credentials come from the environment with the previous
    # hardcoded values as defaults, so existing setups keep working
    # until .env overrides them.
def get_connection():
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "172.20.0.20"),
        port=int(os.environ.get("PGPORT", "5432")),
        database=os.environ.get("PGDATABASE", "network_logs"),
        user=os.environ.get("PGUSER", "monitor"),
        password=os.environ.get("PGPASSWORD", "monitor"),
        connect_timeout=int(os.environ.get("PGCONNECT_TIMEOUT", "3")),
        options="-c search_path=public"
    )


LOG_COLUMNS = (
    "timestamp", "hostname", "facility", "severity",
    "device_type", "event", "src_ip", "dst_ip", "proto", "dst_port", "raw_line",
)


    # Project a parsed log dict onto LOG_COLUMNS in order.
def _entry_tuple(entry):
    return tuple(entry.get(col) for col in LOG_COLUMNS)


    # Insert a single log entry into the logs table.
def insert_log_entry(cursor, entry):
    cursor.execute("""
        INSERT INTO logs (timestamp, hostname, facility, severity,
                         device_type, event, src_ip, dst_ip, proto, dst_port, raw_line)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, _entry_tuple(entry))


    # Insert multiple log entries with one roundtrip.
def insert_log_batch(cursor, entries):
    entries = list(entries)
    if not entries:
        return
    if len(entries) == 1:
        insert_log_entry(cursor, entries[0])
        return
    execute_values(
        cursor,
        "INSERT INTO logs (timestamp, hostname, facility, severity,"
        " device_type, event, src_ip, dst_ip, proto, dst_port, raw_line)"
        " VALUES %s",
        [_entry_tuple(e) for e in entries],
    )


    # Query logs from the last N seconds.
    #
    # Args:
    # cursor: psycopg2 cursor
    # window_seconds: how far back to query
    #
    # Returns:
    # list of dicts with log data
def query_window(cursor, window_seconds=60):
    cursor.execute("""
        SELECT timestamp, hostname, facility, severity,
               device_type, event, src_ip, dst_ip, proto, dst_port
        FROM logs
        WHERE timestamp >= NOW() - make_interval(secs => %s)
        ORDER BY timestamp
    """, (window_seconds,))

    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


    # Insert a detected anomaly into the anomalies table.
    #
    # Args:
    # cursor: psycopg2 cursor
    # anomaly: dict with severity, description, anomaly_score, features
    # window_seconds: size of the detection window (window_end - window_start)
    #
    # Returns:
    # id of the inserted row
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


    # Fold a repeat detection into an existing anomaly row.
    #
    # Refreshes window_end and records repeat_count/last_seen in features,
    # so sustained attacks show as one row with "seen Nx" instead of clones.
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
