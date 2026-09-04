# Anomaly detector coordinator.
#
# Orchestrates the three detection layers:
# Layer 2a: Rules Engine (instant)
# Layer 2b: Isolation Forest ML (instant)
# Layer 2c: Llama 3.2 11B LLM API (async, only on HIGH/CRITICAL)

from pipeline.llm_engine import call_llm
from pipeline.ml_engine import extract_features, load_model, detect_ml
from pipeline.rules_engine import detect_rules
from db.init import get_connection, query_window, insert_anomaly, bump_anomaly
import sys
import time
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


WINDOW_INTERVAL = 15  # seconds between detection cycles
WINDOW_SIZE = 30  # seconds of logs to query
LLM_COOLDOWN = 300  # seconds before re-calling LLM for the same signature
INSERT_COOLDOWN = 300  # seconds before inserting a new row for the same signature

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

running = True
_last_llm = {}  # (rule-signature) -> monotonic timestamp of last LLM call
_last_insert = {}  # (rule-signature) -> (anomaly_id, repeat_count, monotonic timestamp)


    # Build a hashable key so repeats of the same attack cool down.
def llm_signature(rule_hits, ml_severity):
    parts = tuple(sorted(
        (h.get("type", "?"), str(h.get("src_ip", "-"))) for h in rule_hits
    ))
    return (parts, ml_severity)


    # True if this signature hasn't triggered an LLM call recently.
def cooldown_expired(key, now=None):
    now = time.monotonic() if now is None else now
    return (now - _last_llm.get(key, 0.0)) >= LLM_COOLDOWN


    # Merge results from all three layers into one anomaly record.
    #
    # Returns:
    # dict with severity, description, anomaly_score, features
    # or None if nothing flagged
def combine_results(rule_hits, ml_score, ml_severity, llm_result):
    max_severity = "LOW"
    descriptions = []
    affected_ips = set()

    # Layer 2a: Rule hits
    for hit in rule_hits:
        descriptions.append(f"[RULE] {hit['description']}")
        if hit.get("src_ip"):
            affected_ips.add(str(hit["src_ip"]))
        if SEV_RANK.get(hit["severity"], 0) > SEV_RANK[max_severity]:
            max_severity = hit["severity"]

    # Layer 2b: ML score
    if ml_severity != "LOW":
        descriptions.append(f"[ML] Anomaly score: {ml_score} ({ml_severity})")
        if SEV_RANK.get(ml_severity, 0) > SEV_RANK[max_severity]:
            max_severity = ml_severity

    # Layer 2c: LLM result
    if llm_result and llm_result.get("anomalies"):
        for a in llm_result["anomalies"]:
            conf = a.get("confidence", 0)
            descriptions.append(
                f"[LLM] {a.get('type', 'UNKNOWN')}: {
                    a.get('description', '')} "
                f"(confidence: {conf})"
            )
            for ip in a.get("affected_ips", []):
                affected_ips.add(str(ip))
            if SEV_RANK.get(a.get("severity", "LOW"), 0) > SEV_RANK[max_severity]:
                max_severity = a["severity"]

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
            "llm_anomalies": len(llm_result.get("anomalies", [])) if llm_result else 0,
            "affected_ips": list(affected_ips),
        }),
    }


    # Main detection loop — run as a daemon thread from orchestrator.
    #
    # Args:
    # interval: seconds between detection cycles
def start_detector(interval=WINDOW_INTERVAL):
    global running

    print("[DETECTOR] Starting anomaly detector", file=sys.stderr)

    # Load ML model (optional — rules still work without it)
    model = load_model()
    if model:
        print("[DETECTOR] Loaded Isolation Forest model", file=sys.stderr)
    else:
        print("[DETECTOR] No ML model found — ML layer disabled", file=sys.stderr)

    conn = get_connection()
    cursor = conn.cursor()

    while running:
        try:
            # 1. Query the last WINDOW_SIZE seconds of logs
            rows = query_window(cursor, WINDOW_SIZE)
            if not rows:
                time.sleep(interval)
                continue

            # 2. Layer 2a: Rule-based detection (instant)
            rule_hits = detect_rules(rows)

            # 3. Layer 2b: ML detection (instant)
            features = extract_features(rows)
            ml_score, ml_severity = detect_ml(features, model)

            # 4. Layer 2c: LLM deep analysis (only if HIGH/CRITICAL, with cooldown)
            llm_result = None
            if rule_hits or ml_severity in ("HIGH", "CRITICAL"):
                key = llm_signature(rule_hits, ml_severity)
                if cooldown_expired(key):
                    context = {
                        "rule_hits": rule_hits,
                        "ml_score": ml_score,
                        "ml_severity": ml_severity,
                        "window_events": len(rows),
                    }
                    llm_result = call_llm(rows, context)
                    _last_llm[key] = time.monotonic()
                else:
                    print("[DETECTOR] LLM cooldown — skipping repeat signature", file=sys.stderr)

            # 5. Combine all results
            anomaly = combine_results(
                rule_hits, ml_score, ml_severity, llm_result)

            # 6. Insert if something was flagged (merge repeats into one row)
            if anomaly:
                key = llm_signature(rule_hits, ml_severity)
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

        except Exception as e:
            print(f"[DETECTOR] Error: {e}", file=sys.stderr)
            try:
                conn.rollback()
            except Exception:
                pass

        time.sleep(interval)

    cursor.close()
    conn.close()
    print("[DETECTOR] Stopped", file=sys.stderr)
