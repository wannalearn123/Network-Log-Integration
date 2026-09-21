#!/usr/bin/env python3
# Train Isolation Forest model on live log data from PostgreSQL.
# Usage: .venv/bin/python train/train_model.py [--hours 8] [--limit 200000]

import sys
import bisect
import csv
import json
import pickle
import argparse
import datetime
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.ml_engine import MODEL_PATH, WINDOW_SECONDS
from db.init import get_connection


# ── Window feature extractor (14 metrics) ─────────────────────────────
# Lives here (not in ml_engine): the engine is a neutral scoring shell and
# knows no feature set. Only the window-path trainers use this.
FEATURE_COUNT = 14  # base + temporal (rate_delta, rate_ratio, is_burst)

_prev_window_counts = []  # state for temporal feature computation


# Extract 14-feature vector from log rows. Events normalized to uppercase.
def extract_features(rows):
    total = len(rows) or 1
    ev = [(r.get("event") or "").upper() for r in rows]
    curr = len(rows) or 1
    prev = _prev_window_counts[-1] if _prev_window_counts else curr

    # Temporal features
    rate_delta = (curr - prev) / max(WINDOW_SECONDS, 1)
    rate_ratio = curr / max(prev, 0.001)
    is_burst = 1.0 if curr > 3.0 * prev else 0.0

    # Update state before returning
    _prev_window_counts.append(curr)

    return np.array([[
        len(rows),                                                    # total_events
        sum(1 for e in ev if e in ("FW_DROP", "FW_BLOCK")),           # fw_drop_count
        sum(1 for e in ev if e in ("FW_ALLOW", "FW_ACCEPT")),         # fw_allow_count
        sum(1 for e in ev if "SCAN" in e),                            # scan_detected
        sum(1 for e in ev if "FAILED" in e or "BRUTE" in e            # brute_detected
                             or "DEAUTH" in e or "AUTH_FAILURE" in e),
        len(set(r.get("src_ip") for r in rows if r.get("src_ip"))),  # unique_src_ips
        len(set(r.get("dst_port") for r in rows if r.get("dst_port"))),# unique_dst_ports
        sum(1 for r in rows if r.get("proto") == "TCP") / total,     # tcp_ratio
        sum(1 for r in rows if r.get("proto") == "UDP") / total,     # udp_ratio
        sum(1 for r in rows if r.get("proto") == "ICMP") / total,    # icmp_ratio
        sum(1 for r in rows                                         # high_sev_ratio
            if (r.get("severity") or "").upper()
            in ("EMERG", "ALERT", "CRIT", "ERR", "CRITICAL", "ERROR")) / total,
        rate_delta,                                                    # temporal: rate_delta
        rate_ratio,                                                    # temporal: rate_ratio
        is_burst,                                                      # temporal: is_burst
    ]])


FEATURE_NAMES = [
    "total_events",
    "fw_drop_count",
    "fw_allow_count",
    "scan_detected",
    "brute_detected",
    "unique_src_ips",
    "unique_dst_ports",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "high_sev_ratio",
    "rate_delta",          # current_rate - previous_rate
    "rate_ratio",          # current_rate / previous_rate
    "is_burst",            # 1 if rate > 3x previous, else 0
]


def fetch_rows_from_db(hours=8, limit=200000):
    """Fetch live log rows from PostgreSQL, ordered by timestamp."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp, hostname, facility, severity,
               device_type, event, src_ip, dst_ip, proto, dst_port
        FROM logs
        WHERE device_type = 'firewall'
          AND timestamp >= NOW() - make_interval(hours => %s)
        ORDER BY timestamp ASC
        LIMIT %s
    """, (hours, limit))
    cols = [d[0] for d in cur.description]
    rows = []
    for rec in cur.fetchall():
        r = dict(zip(cols, rec))
        if r.get("src_ip") is not None:
            r["src_ip"] = str(r["src_ip"])
        if r.get("dst_ip") is not None:
            r["dst_ip"] = str(r["dst_ip"])
        ts = r.get("timestamp")
        if isinstance(ts, datetime.datetime) and ts.tzinfo is None:
            r["timestamp"] = ts.replace(tzinfo=datetime.timezone.utc)
        rows.append(r)
    cur.close()
    conn.close()
    return rows


# ── Manifest-based ground truth ─────────────────────────────────────
# replay_dataset.sh writes one row per attack line it emits:
#   timestamp,src_ip,label   (ISO-8601, naive or +00:00)
# Cached per path; missing file → empty list (keyword/pattern fallback).
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "data" / "replay_manifest.csv"

_MANIFEST_CACHE = {}


def _load_manifest_ts(path):
    """Load+sort manifest attack timestamps as epoch seconds."""
    key = str(path)
    if key in _MANIFEST_CACHE:
        return _MANIFEST_CACHE[key]
    ts = []
    try:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                t = (row.get("timestamp") or "").strip()
                if not t:
                    continue
                try:
                    dt = datetime.datetime.fromisoformat(t)
                except ValueError:
                    continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                ts.append(dt.timestamp())
    except FileNotFoundError:
        pass
    ts.sort()
    _MANIFEST_CACHE[key] = ts
    print(f"[TRAIN] Manifest {path}: {len(ts)} attack timestamps")
    return ts


def split_into_windows(rows, window_seconds=WINDOW_SECONDS):
    if not rows:
        return []

    windows = []
    current_window = []
    window_start = rows[0]["timestamp"]

    for row in rows:
        ts = row["timestamp"]
        # Normalize: if one is naive and other is tz-aware, treat naive as UTC
        if window_start.tzinfo is None and ts.tzinfo is not None:
            window_start = window_start.replace(tzinfo=datetime.timezone.utc)
        elif window_start.tzinfo is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)

        elapsed = (ts - window_start).total_seconds()

        if elapsed >= window_seconds:
            if current_window:
                windows.append(current_window)
            current_window = [row]
            window_start = ts
        else:
            current_window.append(row)

    if current_window:
        windows.append(current_window)

    return windows


def label_window(rows, manifest_ts=None, tolerance=WINDOW_SECONDS):
    """Return True if the window contains attack traffic, else False.

    Three sources, in order (any hit labels the window anomalous):
    1. Manifest join (exact): replay_dataset.sh ground truth — a manifest
       attack timestamp inside [window_start - tol, window_end + tol].
    2. Event-name keywords (legacy): named attack events from older feeds.

    NOTE: there is deliberately NO traffic-pattern fallback here. Pattern
    thresholds (e.g. "12 unique ports") are calibrated for live-rate
    windows (~tens of rows); synthetic training windows pack ~1000 rows,
    where benign port variety alone trips them and labels everything
    anomalous. The manifest is exact ground truth — patterns would only
    add false labels.
    """
    if rows:
        if manifest_ts is None:
            manifest_ts = _load_manifest_ts(DEFAULT_MANIFEST)
        if manifest_ts:
            t0, t1 = None, None
            for r in rows:
                ts = r.get("timestamp")
                if ts is None:
                    continue
                if isinstance(ts, datetime.datetime) and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
                e = ts.timestamp()
                t0 = e if t0 is None or e < t0 else t0
                t1 = e if t1 is None or e > t1 else t1
            if t0 is not None:
                i = bisect.bisect_left(manifest_ts, t0 - tolerance)
                if i < len(manifest_ts) and manifest_ts[i] <= t1 + tolerance:
                    return True
        # 2. Keyword fallback (named attack events)
        ATTACK_EVENTS = {
            "DDOS_FLOOD", "DDOS", "DOS", "BRUTE_FORCE", "BRUTE",
            "SCAN_DETECTED", "SCAN", "PORT_SCAN", "NETWORK_SCAN",
            "DEAUTH", "AUTH_FAILURE", "FAILED_LOGIN",
            "MALWARE", "EXFIL", "C2_BEACON", "RANSOMWARE",
            "SQL_INJECTION", "XSS", "CMD_INJECTION",
        }
        events = {(r.get("event") or "").upper() for r in rows}
        if any(e in ATTACK_EVENTS or any(a in e for a in ATTACK_EVENTS)
               for e in events):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on live log data from PostgreSQL")
    parser.add_argument("--hours", type=int, default=8,
                        help="Hours of live data to fetch from database (default: 8)")
    parser.add_argument("--limit", type=int, default=400000,
                        help="Max rows to fetch from database (default: 400000)")
    parser.add_argument("--manifest", type=str, default=str(DEFAULT_MANIFEST),
                        help="Replay ground-truth CSV for window labels "
                             "(default: train/data/replay_manifest.csv)")
    parser.add_argument("--window-seconds", type=int, default=WINDOW_SECONDS,
                        help=f"Window size in seconds (default: {WINDOW_SECONDS})")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected anomaly ratio (default: 0.05)")
    parser.add_argument("--test-ratio", type=float, default=0.2,
                        help="Fraction of data for test set (default: 0.2)")
    args = parser.parse_args()

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    import datetime

    # 1. Fetch live data from PostgreSQL
    print(f"[TRAIN] Fetching last {args.hours}h (limit {args.limit}) from PostgreSQL...")
    rows = fetch_rows_from_db(args.hours, args.limit)
    print(f"[TRAIN] Found {len(rows)} total log entries")

    if len(rows) < 10:
        print("[TRAIN] Not enough data — need at least 10 entries")
        sys.exit(1)

    # 2. Split into windows
    windows = split_into_windows(rows, args.window_seconds)
    print(f"[TRAIN] Split into {len(windows)} windows ({args.window_seconds}s each)")

    if len(windows) < 3:
        print("[TRAIN] Not enough windows — need at least 3")
        sys.exit(1)

    # 3. Extract 14 features (11 base + 3 temporal from ml_engine)
    print("[TRAIN] Extracting features...")
    features = []
    for w in windows:
        bf = np.asarray(extract_features(w)).reshape(1, -1)
        features.append(bf)

    X = np.vstack(features)
    print(f"[TRAIN] Feature matrix: {X.shape[0]} samples x {X.shape[1]} features")

    # 3c. Validate feature count
    if X.shape[1] != FEATURE_COUNT:
        print(f"[TRAIN] WARNING: Expected {FEATURE_COUNT} features, got {X.shape[1]}")
        print(f"[TRAIN]   Model may not match detector — retrain after code update")

    # 4. Label windows via manifest join (+ keyword/pattern fallback)
    manifest_ts = _load_manifest_ts(args.manifest)
    labels = np.array([label_window(w, manifest_ts, args.window_seconds)
                       for w in windows])
    n_anomaly = int(labels.sum())
    n_normal = len(labels) - n_anomaly
    print(f"[TRAIN] Labels: {n_normal} normal, {n_anomaly} anomaly "
          f"({n_anomaly/len(labels)*100:.1f}% attack rate)")

    # 5. Train/test split (stratified if possible)
    if n_anomaly >= 2:
        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X, labels, np.arange(len(labels)),
            test_size=args.test_ratio, random_state=42, stratify=labels)
    else:
        # Not enough anomalies for stratified split — use random split
        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X, labels, np.arange(len(labels)),
            test_size=args.test_ratio, random_state=42)

    print(f"[TRAIN] Train/test split: {len(X_train)} train, {len(X_test)} test")
    print(f"[TRAIN]   Train: {int(y_train.sum())} anomaly, {len(y_train)-int(y_train.sum())} normal")
    print(f"[TRAIN]   Test:  {int(y_test.sum())} anomaly, {len(y_test)-int(y_test.sum())} normal")

    # 6. Scale features (fit on train only, transform both)
    print("[TRAIN] Fitting StandardScaler on train set...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    for name, mean, scale in zip(FEATURE_NAMES, scaler.mean_, scaler.scale_):
        print(f"  {name:16s} mean={mean:10.4f} scale={scale:10.4f}")

    # 7. Train Isolation Forest on train set only
    print(f"[TRAIN] Training IsolationForest (contamination={args.contamination})...")
    clf = IsolationForest(
        contamination=args.contamination,
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_s)

    # 8. Evaluate on train set (in-sample)
    train_scores = clf.decision_function(X_train_s)
    train_pred = clf.predict(X_train_s)
    train_anomaly = sum(1 for p in train_pred if p == -1)
    print(f"[TRAIN] Train set: {train_anomaly} predicted anomaly "
          f"(score range: {train_scores.min():.4f} to {train_scores.max():.4f})")

    # 8b. Overfitting check: compare train vs test ROC-AUC
    from sklearn.metrics import roc_auc_score
    train_anomaly_scores = -train_scores  # negate: anomalies = higher values
    if int(y_train.sum()) > 0:
        train_roc_auc = roc_auc_score(y_train.astype(int), train_anomaly_scores)
        print(f"[TRAIN] Train ROC-AUC: {train_roc_auc:.4f}")
    else:
        train_roc_auc = None

    # 9. Evaluate on test set (out-of-sample) — PRIMARY METRIC: ROC-AUC
    test_scores = clf.decision_function(X_test_s)
    test_anomaly_scores = -test_scores  # negate: anomalies = higher values

    if int(y_test.sum()) > 0:
        test_roc_auc = roc_auc_score(y_test.astype(int), test_anomaly_scores)
        print(f"[TRAIN] Test ROC-AUC:  {test_roc_auc:.4f}")

        # Overfitting verdict
        if train_roc_auc is not None:
            gap = train_roc_auc - test_roc_auc
            print(f"[TRAIN] Overfitting check: train={train_roc_auc:.4f} test={test_roc_auc:.4f} gap={gap:.4f}")
            if gap < 0.05:
                print("[TRAIN] ✅ Minimal overfitting — model generalizes well")
            elif gap < 0.10:
                print("[TRAIN] ⚠️  Mild overfitting — acceptable for most use cases")
            else:
                print("[TRAIN] ❌ Significant overfitting — consider reducing features or increasing data")
    else:
        test_roc_auc = None
        print("[TRAIN] Test set has no anomalies — skipping ROC-AUC")

    test_pred = clf.predict(X_test_s)
    test_anomaly = sum(1 for p in test_pred if p == -1)
    print(f"[TRAIN] Test set: {test_anomaly} predicted anomaly "
          f"(score range: {test_scores.min():.4f} to {test_scores.max():.4f})")

    # 10. Save test set for evaluation script
    test_set_path = Path(__file__).resolve().parent / "data" / "test_set.jsonl"
    test_set_path.parent.mkdir(parents=True, exist_ok=True)
    with open(test_set_path, "w") as f:
        for i, idx in enumerate(idx_test):
            record = {
                "window_idx": int(idx),
                "label": "anomaly" if y_test[i] else "normal",
                "features": X_test[i].tolist(),
                "raw_score": float(test_scores[i]),
                "anomaly_score": float(test_anomaly_scores[i]),
            }
            f.write(json.dumps(record) + "\n")
    print(f"[TRAIN] Saved test set to {test_set_path} ({len(idx_test)} windows)")

    # 11. Feature importance via decision_function variance (on train set)
    if len(X_train_s) >= 10:
        base_score = float(np.mean(clf.decision_function(X_train_s)))
        importances = []
        for col in range(X_train_s.shape[1]):
            X_perm = X_train_s.copy()
            np.random.seed(42)
            np.random.shuffle(X_perm[:, col])
            perm_score = float(np.mean(clf.decision_function(X_perm)))
            importances.append(abs(base_score - perm_score))
        importances = np.array(importances)
        print(f"[TRAIN] Feature importance (top 5):")
        indices = np.argsort(importances)[::-1]
        for i in indices[:5]:
            print(f"  {FEATURE_NAMES[i]:16s} {importances[i]:.4f}")

    # 12. Compute severity thresholds from train score distribution
    import math
    anomaly_scores_train = 1.0 / (1.0 + np.exp(-5.0 * (-train_scores)))
    t_med = float(round(float(np.quantile(anomaly_scores_train, 0.90)), 4))
    t_high = float(round(float(np.quantile(anomaly_scores_train, 0.95)), 4))
    t_crit = float(round(float(np.quantile(anomaly_scores_train, 0.99)), 4))
    print(f"[TRAIN] Severity cuts: MEDIUM>={t_med} HIGH>={t_high} CRITICAL>={t_crit}")
    thresholds = {"medium": t_med, "high": t_high, "critical": t_crit}

    # 13. Save model bundle
    import sklearn

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    if MODEL_PATH.exists():
        backup = MODEL_PATH.with_suffix(".prev.pkl")
        backup.write_bytes(MODEL_PATH.read_bytes())
        print(f"[TRAIN] Backed up previous model to {backup}")
    bundle = {
        "model": clf,
        "scaler": scaler,
        "thresholds": thresholds,
        "sigmoid_k": 5,
        "feature_names": FEATURE_NAMES,
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "window_seconds": args.window_seconds,
        "contamination": args.contamination,
    }
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)

    print(f"[TRAIN] Model saved to {MODEL_PATH}")

    # 14. Final summary
    print()
    print("=" * 50)
    print("  TRAINING SUMMARY")
    print("=" * 50)
    print(f"  Train windows:    {len(X_train)}")
    print(f"  Test windows:     {len(X_test)}")
    print(f"  Anomaly (train):  {int(y_train.sum())} ({y_train.mean()*100:.1f}%)")
    print(f"  Anomaly (test):   {int(y_test.sum())} ({y_test.mean()*100:.1f}%)")
    if test_roc_auc is not None:
        print(f"  Test ROC-AUC:     {test_roc_auc:.4f}")
        if test_roc_auc > 0.8:
            print("  ✅ Good separation between normal and anomaly")
        elif test_roc_auc > 0.6:
            print("  ⚠️  Moderate separation — consider more data or tuning")
        else:
            print("  ❌ Weak separation — check features or data quality")
    print()
    print(f"[TRAIN] Restart the orchestrator to use the trained model")


if __name__ == "__main__":
    main()
