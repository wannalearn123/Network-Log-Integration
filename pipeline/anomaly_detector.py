"""Rules-first detector with interruptible scheduling and per-entity cooldowns."""
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg2
from db.init import (get_connection_retry, query_window, insert_anomaly,
                     bump_anomaly, prune_history, cooldown_signature,
                     get_cooldown, save_cooldown)
from pipeline.rules_engine import detect_rules, THRESHOLD_VERSION
from pipeline.notifier import notify

WINDOW_INTERVAL = 15
WINDOW_SIZE = 30
INSERT_COOLDOWN = 300
INSERT_COOLDOWN_FLOOD = 60
SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def merge_signature(hit):
    return (hit.get("type", "?"), str(hit.get("entity") or hit.get("src_ip") or "-"))


def _cooldown_for(hit):
    return INSERT_COOLDOWN_FLOOD if hit.get("type") in ("FLOOD", "HIGH_DROP_RATE") else INSERT_COOLDOWN


def make_anomaly(hit, rows, window_seconds=WINDOW_SIZE):
    return {
        "severity": hit["severity"],
        "description": f"[RULE] {hit['description']}",
        "anomaly_score": None,
        "features": json.dumps({
            "type": hit["type"],
            "entity": hit.get("entity") or hit.get("src_ip"),
            "window_seconds": window_seconds,
            "event_rate": len(rows) / window_seconds,
            "threshold_version": THRESHOLD_VERSION,
            "repeat_count": 1,
        }),
    }


def start_detector(interval=WINDOW_INTERVAL, stop_event=None):
    stop_event = stop_event or threading.Event()
    conn = get_connection_retry(stop_event)
    if conn is None:
        return
    last_prune = 0.0
    try:
        with conn.cursor() as cursor:
            while not stop_event.is_set():
                try:
                    now = time.monotonic()
                    if now - last_prune >= 3600:
                        prune_history(cursor)
                        conn.commit()
                        last_prune = now
                    rows = query_window(cursor, WINDOW_SIZE)
                    conn.commit()
                    hits = sorted(detect_rules(rows, WINDOW_SIZE),
                                  key=lambda h: SEV_RANK[h["severity"]], reverse=True)
                    for hit in hits:
                        if stop_event.is_set():
                            break
                        signature = cooldown_signature(hit)
                        previous = get_cooldown(cursor, signature)
                        age = float(previous[2]) if previous else None
                        if previous and age < _cooldown_for(hit):
                            anomaly_id, count, _ = previous
                            bump_anomaly(cursor, anomaly_id, count + 1)
                            save_cooldown(cursor, signature, anomaly_id, count + 1)
                            conn.commit()
                        else:
                            anomaly = make_anomaly(hit, rows)
                            anomaly_id = insert_anomaly(cursor, anomaly, WINDOW_SIZE)
                            save_cooldown(cursor, signature, anomaly_id, 1)
                            conn.commit()
                            print(f"[DETECTOR] {anomaly['description']}", file=sys.stderr)
                            notify(anomaly["severity"], anomaly["description"], anomaly_id)
                except (psycopg2.OperationalError, psycopg2.InterfaceError):
                    raise  # Orchestrator reports failed worker and shuts down cleanly.
                except Exception as exc:
                    conn.rollback()
                    print(f"[DETECTOR] Error: {exc}", file=sys.stderr)
                stop_event.wait(interval)
    finally:
        conn.close()


if __name__ == "__main__":
    import signal
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    start_detector(stop_event=stop)
