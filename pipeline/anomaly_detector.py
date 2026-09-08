# Anomaly detector coordinator — orchestrates rules + ML detection layers.

import sys
import time
import json
import psycopg2
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.ml_engine import extract_features, load_model, detect_ml
from pipeline.rules_engine import detect_rules
from db.init import get_connection, query_window, insert_anomaly, bump_anomaly


WINDOW_INTERVAL = 15  # seconds between detection cycles
WINDOW_SIZE = 30  # seconds of logs to query
INSERT_COOLDOWN = 300  # seconds before inserting a new row for the same signature

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

running = True
_last_insert = {}  # (rule-signature) -> (anomaly_id, repeat_count, monotonic timestamp)


    # Build a hashable key so repeats of the same attack merge.
def merge_signature(rule_hits, ml_severity):
    parts = tuple(sorted(
        (h.get("type", "?"), str(h.get("src_ip", "-"))) for h in rule_hits
    ))
    return (parts, ml_severity)


    # Merge results from rules + ML into one anomaly record, or None.
def combine_results(rule_hits, ml_score, ml_severity):
    max_severity = "LOW"
    descriptions = []
    affected_ips = set()

    # Layer 1: Rule hits
    for hit in rule_hits:
        descriptions.append(f"[RULE] {hit['description']}")
        if hit.get("src_ip"):
            affected_ips.add(str(hit["src_ip"]))
        if SEV_RANK.get(hit["severity"], 0) > SEV_RANK[max_severity]:
            max_severity = hit["severity"]

    # Layer 2: ML score
    if ml_severity != "LOW":
        descriptions.append(f"[ML] Anomaly score: {ml_score} ({ml_severity})")
        if SEV_RANK.get(ml_severity, 0) > SEV_RANK[max_severity]:
            max_severity = ml_severity

    if not descriptions:
        return None

    return {
        "severity": max_severity,
        "description": " | ".join(descriptions),
        "anomaly_score": ml_score,
        "features": json.dumps({
            "rule_hits": len(rule_hits),
            "ml_score": ml_score,
            "ml_severity": ml_severity,
            "affected_ips": list(affected_ips),
        }),
    }


    # Main detection loop — run as daemon thread from orchestrator.
def start_detector(interval=WINDOW_INTERVAL):
    global running

    print("[DETECTOR] Starting anomaly detector", file=sys.stderr)

    # Load ML model (optional — rules still work without it)
    model = load_model()
    if model:
        print("[DETECTOR] Loaded Isolation Forest model", file=sys.stderr)
    else:
        print("[DETECTOR] No ML model found — ML layer disabled", file=sys.stderr)

    try:
        conn = get_connection()
    except Exception as e:
        print(f"[DETECTOR] FATAL: PostgreSQL unreachable: {e}", file=sys.stderr)
        raise
    cursor = conn.cursor()

    while running:
        try:
            # 1. Query the last WINDOW_SIZE seconds of logs
            rows = query_window(cursor, WINDOW_SIZE)
            if not rows:
                time.sleep(interval)
                continue

            # 1. Layer 1: Rule-based detection (instant)
            rule_hits = detect_rules(rows)

            # 2. Layer 2: ML detection (instant)
            features = extract_features(rows)
            ml_score, ml_severity = detect_ml(features, model)

            # 3. Combine all results
            anomaly = combine_results(rule_hits, ml_score, ml_severity)

            # 4. Insert if something was flagged (merge repeats into one row)
            if anomaly:
                key = merge_signature(rule_hits, ml_severity)
                now = time.monotonic()
                prev = _last_insert.get(key)
                if prev is not None and (now - prev[2]) < INSERT_COOLDOWN:
                    anomaly_id, count, _ = prev
                    bump_anomaly(cursor, anomaly_id, count + 1)
                    conn.commit()
                    _last_insert[key] = (anomaly_id, count + 1, now)
                    print(
                        f"[DETECTOR] Repeat [{anomaly['severity']}] "
                        f"(x{count + 1}) — merged into anomaly {anomaly_id}",
                        file=sys.stderr,
                    )
                else:
                    anomaly_id = insert_anomaly(cursor, anomaly, window_seconds=WINDOW_SIZE)
                    conn.commit()
                    _last_insert[key] = (anomaly_id, 1, now)
                    print(
                        f"[DETECTOR] Anomaly [{anomaly['severity']}]: "
                        f"{anomaly['description']}",
                        file=sys.stderr,
                    )
            else:
                print("[DETECTOR] Window clean — no anomalies", file=sys.stderr)

        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            print(f"[DETECTOR] FATAL: database connection lost: {e}", file=sys.stderr)
            running = False
            break
        except Exception as e:
            print(f"[DETECTOR] Error: {e}", file=sys.stderr)
            try:
                conn.rollback()
            except Exception:
                pass

        time.sleep(interval)

    try:
        cursor.close()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass
    print("[DETECTOR] Stopped", file=sys.stderr)
