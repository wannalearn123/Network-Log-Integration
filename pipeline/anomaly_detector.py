# Anomaly detector coordinator — rules engine (primary) + ML engine

from db.init import get_connection, query_window, insert_anomaly, bump_anomaly
from pipeline.rules_engine import detect_rules, THRESHOLD_VERSION
from pipeline.notifier import notify
import sys
import time
import json
import psycopg2
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.ml_engine import classify_window_jev

WINDOW_INTERVAL = 15  # seconds between detection cycles
WINDOW_SIZE = 30  # seconds of logs to query
INSERT_COOLDOWN = 300  # seconds before inserting a new row for the same per-IP signature
INSERT_COOLDOWN_FLOOD = 60  # shorter cooldown for aggregate FLOOD / HIGH_DROP_RATE

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
MAX_COOLDOWN = max(INSERT_COOLDOWN, INSERT_COOLDOWN_FLOOD)  # 300s

running = True
# (rule-signature) -> (anomaly_id, repeat_count, monotonic timestamp)
_last_insert = {}

# Remove stale entries to prevent unbounded memory growth.
def _prune_last_insert():
    now = time.monotonic()
    stale = [k for k, v in _last_insert.items() if (now - v[2]) > MAX_COOLDOWN]
    for k in stale:
        del _last_insert[k]
    if stale:
        print(f"[DETECTOR] Pruned {len(stale)} stale cooldown entries "
              f"({len(_last_insert)} remaining)", file=sys.stderr)

def merge_signature(hit):
    h_type = hit.get("type", "?")
    entity = str(hit.get("entity") or hit.get("src_ip") or "-")
    bucket_min = int(time.time() // 60)
    return (h_type, entity, bucket_min)


def _cooldown_for(hit):
    if hit.get("type") in ("FLOOD", "HIGH_DROP_RATE") and not hit.get("src_ip"):
        return INSERT_COOLDOWN_FLOOD  # 60s, aggregate
    return INSERT_COOLDOWN  # 300s, attributed

def combine_results(ranked_hits, ml_score, ml_severity, rows=None, window_seconds=WINDOW_SIZE,
                    ml_detail=None):
    # One anomaly dict per hit (caller sorts by severity first). The ML
    # second opinion attaches to the top hit only.
    out = []
    for i, hit in enumerate(ranked_hits):
        descriptions = [f"[RULE] {hit['description']}"]
        severity = hit.get("severity", "LOW")
        attach_ml = (i == 0 and ml_score and ml_severity != "LOW")
        if attach_ml:
            n = (ml_detail or {}).get("scored", "?")
            descriptions.append(
                f"[ML] firewall max score {ml_score:.3f} → {ml_severity} (n={n})")
            if SEV_RANK.get(ml_severity, 0) > SEV_RANK.get(severity, 0):
                severity = ml_severity
        ent = hit.get("entity") or hit.get("src_ip")
        out.append({
            "severity": severity,
            "description": " | ".join(descriptions),
            "anomaly_score": ml_score if attach_ml else 0.0,
            "features": json.dumps({
                "type": hit.get("type"),
                "entity": str(ent) if ent else None,
                "window_seconds": window_seconds,
                "event_rate": (len(rows) / max(1, window_seconds)) if rows is not None else None,
                "threshold_version": THRESHOLD_VERSION,
                "ml_score": ml_score if attach_ml else 0.0,
                "ml_severity": ml_severity if attach_ml else "LOW",
                "ml_scored": (ml_detail or {}).get("scored"),
                "ml_high": (ml_detail or {}).get("high"),
            }),
        })
    return out

def start_detector(interval=WINDOW_INTERVAL):
    global running

    print("[DETECTOR] Starting anomaly detector", file=sys.stderr)

    try:
        conn = get_connection()
    except Exception as e:
        print(f"[DETECTOR] FATAL: PostgreSQL unreachable: {
              e}", file=sys.stderr)
        raise
    cursor = conn.cursor()

    while running:
        _prune_last_insert()
        try:
            rows = query_window(cursor, WINDOW_SIZE)
            try:
                conn.commit()
            except Exception:
                pass
            if not rows:
                time.sleep(interval)
                continue

            rows_with_ip = [r for r in rows
                              if r.get('src_ip') or r.get('mac') or r.get('client_mac')
                              or r.get('event') == 'stp_event']
            rule_hits = detect_rules(rows_with_ip, WINDOW_SIZE)

            ml_score = 0.0
            ml_severity = "LOW"
            ml_detail = {"scored": 0, "high": 0}

            ranked_hits = sorted(
                rule_hits,
                key=lambda h: SEV_RANK.get(h.get("severity", "LOW"), 0),
                reverse=True,
            )
            anomalies = combine_results(
                ranked_hits, ml_score, ml_severity, rows, WINDOW_SIZE, ml_detail)

            if anomalies:
                for hit, anomaly in zip(ranked_hits, anomalies):
                    key = merge_signature(hit)
                    now = time.monotonic()
                    cooldown = _cooldown_for(hit)
                    prev = _last_insert.get(key)
                    if prev is not None and (now - prev[2]) < cooldown:
                        anomaly_id, count, _ = prev
                        bump_anomaly(cursor, anomaly_id, count + 1)
                        try:
                            conn.commit()
                        except Exception:
                            conn.rollback()
                            raise
                        _last_insert[key] = (anomaly_id, count + 1, now)
                        print(
                            f"[DETECTOR] Repeat [{anomaly['severity']}] "
                            f"(x{count + 1}) — merged into anomaly {anomaly_id}",
                            file=sys.stderr,
                        )
                    else:
                        anomaly_id = insert_anomaly(
                            cursor, anomaly, window_seconds=WINDOW_SIZE)
                        try:
                            conn.commit()
                        except Exception:
                            conn.rollback()
                            raise
                        _last_insert[key] = (anomaly_id, 1, now)
                        print(
                            f"[DETECTOR] Anomaly [{anomaly['severity']}]: "
                            f"{anomaly['description']}",
                            file=sys.stderr,
                        )
                        notify(
                            anomaly["severity"],
                            anomaly["description"],
                            anomaly_id,
                        )

                # Layer 2: ML second opinion — one noul per window, throttled
                # to one row per minute. Never suppresses a rule hit.
                jev = classify_window_jev(rows)
                if jev:
                    jkey = ("JEV", int(time.time() // 60))
                    jnow = time.monotonic()
                    jprev = _last_insert.get(jkey)
                    janomaly = {
                        "severity": jev["severity"],
                        "description": (
                            f"[JEV] attack likely — P={jev['probability']:.2f} "
                            f"conf={jev['confidence']} · "
                            f"{jev['detail']['events']} events, "
                            f"{jev['detail']['entities']} entities, "
                            f"top {jev['detail']['top_entity']} "
                            f"({jev['detail']['top_entity_events']}) "
                            f"in {WINDOW_SIZE}s"),
                        "anomaly_score": jev["probability"],
                        "features": json.dumps({
                            "type": "ML_JEV",
                            "window_seconds": WINDOW_SIZE,
                            "event_rate": len(rows) / max(1, WINDOW_SIZE),
                            "threshold_version": THRESHOLD_VERSION,
                            "ml_probability": jev["probability"],
                            "ml_confidence": jev["confidence"],
                            "ml_model": jev["model"],
                            "ml_detail": jev["detail"],
                        }),
                    }
                    if jprev is not None and (jnow - jprev[2]) < INSERT_COOLDOWN_FLOOD:
                        jid, jcount, _ = jprev
                        bump_anomaly(cursor, jid, jcount + 1)
                        conn.commit()
                        _last_insert[jkey] = (jid, jcount + 1, jnow)
                        print(f"[DETECTOR] [JEV] repeat (x{jcount + 1}) — "
                              f"merged into anomaly {jid}", file=sys.stderr)
                    else:
                        jid = insert_anomaly(
                            cursor, janomaly, window_seconds=WINDOW_SIZE)
                        conn.commit()
                        _last_insert[jkey] = (jid, 1, jnow)
                        print(f"[DETECTOR] Anomaly [{jev['severity']}]: "
                              f"{janomaly['description']}", file=sys.stderr)
                        notify(jev["severity"], janomaly["description"], jid)
            else:
                print("[DETECTOR] Window clean — no anomalies", file=sys.stderr)

        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            print(f"[DETECTOR] FATAL: database connection lost: {
                  e}", file=sys.stderr)
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
