#!/usr/bin/env python3
# Train Isolation Forest model on collected log data.
# Usage: .venv/bin/python train/train_model.py [--window-minutes 30]

import sys
import pickle
import argparse
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.init import get_connection
from pipeline.ml_engine import MODEL_PATH, WINDOW_SECONDS, extract_features


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
]


def query_all_logs(cursor, minutes):
    cursor.execute("""
        SELECT timestamp, hostname, facility, severity,
               device_type, event, src_ip, dst_ip, proto, dst_port
        FROM logs
        WHERE timestamp >= NOW() - make_interval(mins => %s)
        ORDER BY timestamp
    """, (minutes,))
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def split_into_windows(rows, window_seconds=WINDOW_SECONDS):
    if not rows:
        return []

    windows = []
    current_window = []
    window_start = rows[0]["timestamp"]

    for row in rows:
        ts = row["timestamp"]
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


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on log data")
    parser.add_argument("--window-minutes", type=int, default=30,
                        help="How many minutes of data to use (default: 30)")
    parser.add_argument("--window-seconds", type=int, default=WINDOW_SECONDS,
                        help=f"Window size in seconds (default: {WINDOW_SECONDS}, must match detector)")
    parser.add_argument("--contamination", type=float, default=0.1,
                        help="Expected anomaly ratio (default: 0.1)")
    args = parser.parse_args()

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import datetime

    print(f"[TRAIN] Connecting to PostgreSQL...")
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 1. Query logs
        print(f"[TRAIN] Querying last {args.window_minutes} minutes of logs...")
        rows = query_all_logs(cursor, args.window_minutes)
        print(f"[TRAIN] Found {len(rows)} total log entries")

        if len(rows) < 10:
            print("[TRAIN] Not enough data — need at least 10 entries")
            print("[TRAIN] Let the orchestrator run longer and try again")
            sys.exit(1)

        # 2. Split into windows
        windows = split_into_windows(rows, args.window_seconds)
        print(f"[TRAIN] Split into {len(windows)} windows ({args.window_seconds}s each)")

        if len(windows) < 3:
            print("[TRAIN] Not enough windows — need at least 3")
            print("[TRAIN] Let the orchestrator run longer and try again")
            sys.exit(1)

        # 3. Extract features
        print("[TRAIN] Extracting features...")
        X = np.vstack([np.asarray(extract_features(w)).reshape(1, -1) for w in windows])
        print(f"[TRAIN] Feature matrix: {X.shape[0]} samples x {X.shape[1]} features")

        # 3b. Scale features so counts don't dominate ratios
        print("[TRAIN] Fitting StandardScaler...")
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        for name, mean, scale in zip(FEATURE_NAMES, scaler.mean_, scaler.scale_):
            print(f"  {name:16s} mean={mean:10.4f} scale={scale:10.4f}")

        # 4. Train Isolation Forest on scaled features
        print(f"[TRAIN] Training IsolationForest (contamination={args.contamination})...")
        clf = IsolationForest(
            contamination=args.contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(Xs)

        # 5. Evaluate on training data
        predictions = clf.predict(Xs)  # +1 = normal, -1 = anomaly
        scores = clf.decision_function(Xs)

        n_normal = sum(1 for p in predictions if p == 1)
        n_anomaly = sum(1 for p in predictions if p == -1)

        print(f"[TRAIN] Results:")
        print(f"  Normal windows:  {n_normal}")
        print(f"  Anomaly windows: {n_anomaly}")
        print(f"  Score range:     {scores.min():.4f} to {scores.max():.4f}")

        # Data-driven severity cuts from the training score distribution.
        # Must match ml_engine.detect_ml: sigmoid with k=5.
        import math
        anomaly_scores = 1.0 / (1.0 + np.exp(-5.0 * scores))
        t_med = float(round(float(np.quantile(anomaly_scores, 0.90)), 4))
        t_high = float(round(float(np.quantile(anomaly_scores, 0.95)), 4))
        t_crit = float(round(float(np.quantile(anomaly_scores, 0.99)), 4))
        print(f"[TRAIN] Anomaly-score quantiles:")
        print(f"  p50={float(np.quantile(anomaly_scores, 0.50)):.4f}"
              f" p90={t_med:.4f} p95={t_high:.4f} p99={t_crit:.4f}")
        print(f"[TRAIN] Severity cuts: MEDIUM>={t_med} HIGH>={t_high} CRITICAL>={t_crit}")
        thresholds = {"medium": t_med, "high": t_high, "critical": t_crit}

        # 6. Save model bundle (classifier + scaler)
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
            "feature_names": FEATURE_NAMES,
            "sklearn_version": sklearn.__version__,
            "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "window_seconds": args.window_seconds,
            "contamination": args.contamination,
        }
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(bundle, f)

        print(f"[TRAIN] Model saved to {MODEL_PATH}")
        print(f"[TRAIN] Restart the orchestrator to use the trained model")

    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
