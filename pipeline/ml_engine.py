# ML-based anomaly detection engine — Isolation Forest for unsupervised outlier detection.

import numpy as np
import pickle
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "models" / "isolation_forest.pkl"

# Single source of truth for feature window. Detector and trainer must use this.
# Train distribution == serve distribution; never let the two defaults drift.
WINDOW_SECONDS = 30


    # Extract 11-feature vector from log rows. Events normalized to uppercase.
def extract_features(rows):
    total = len(rows) or 1
    ev = [(r.get("event") or "").upper() for r in rows]

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
    ]])


    # Load pre-trained Isolation Forest bundle from disk. Returns dict or None.
    # If expected_window_seconds is given and the bundle was trained on a
    # different window, refuse it (return None) instead of scoring skewed.
    # Retrain with matching sklearn version after upgrades.
def load_model(expected_window_seconds=None):
    import sklearn

    if not MODEL_PATH.exists():
        return None
    st = MODEL_PATH.stat()
    print(f"[ML] Loading model ({st.st_size} bytes, sklearn {sklearn.__version__})",
          file=sys.stderr)
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)

    if isinstance(bundle, dict):
        trained_window = bundle.get("window_seconds")
        if (expected_window_seconds is not None
                and trained_window is not None
                and int(trained_window) != int(expected_window_seconds)):
            print(f"[ML] Window mismatch: model trained on {trained_window}s, "
                  f"detector uses {expected_window_seconds}s — ML disabled, retrain with "
                  f"--window-seconds {expected_window_seconds}", file=sys.stderr)
            return None
        saved_sklearn = bundle.get("sklearn_version")
        if saved_sklearn and saved_sklearn != sklearn.__version__:
            print(f"[ML] sklearn version mismatch: model={saved_sklearn} runtime={sklearn.__version__} "
                  f"— continuing, retrain recommended", file=sys.stderr)
    return bundle


    # Split a v2 bundle into (clf, scaler, thresholds).
    # thresholds is None for legacy bundles without quantile cuts.
def _unpack_bundle(model):
    if isinstance(model, dict) and "model" in model:
        return model["model"], model.get("scaler"), model.get("thresholds")
    return model, None, None


    # Run Isolation Forest prediction. Returns (anomaly_score 0.0–1.0, severity).
def detect_ml(features, model):
    if model is None:
        return 0.0, "LOW"

    clf, scaler, thresholds = _unpack_bundle(model)
    if scaler is not None:
        features = scaler.transform(features)

    raw_score = clf.decision_function(features)[0]

    # Sigmoid normalization with steepness k=5: maps any decision_function
    # range to (0, 1). k=5 provides good separation between normal (~0.85)
    # and anomalous (~0.1-0.3) scores. Quantile-based thresholds from
    # training ensure correct severity cuts regardless of score range.
    import math
    anomaly_score = float(round(1.0 / (1.0 + math.exp(-5.0 * raw_score)), 4))
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    if thresholds:
        t_crit = float(thresholds.get("critical", 0.85))
        t_high = float(thresholds.get("high", 0.7))
        t_med = float(thresholds.get("medium", 0.5))
    else:
        t_crit, t_high, t_med = 0.85, 0.7, 0.5

    if anomaly_score >= t_crit:
        severity = "CRITICAL"
    elif anomaly_score >= t_high:
        severity = "HIGH"
    elif anomaly_score >= t_med:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return anomaly_score, severity
