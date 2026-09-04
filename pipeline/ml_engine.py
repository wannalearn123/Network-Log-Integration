# ML-based anomaly detection engine.
#
# Uses Isolation Forest for unsupervised anomaly detection.
# Detects statistical outliers that rules might miss.

import numpy as np
import pickle
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "models" / "isolation_forest.pkl"


    # Extract a feature vector from log rows.
    #
    # Normalizes event names to uppercase so lowercase parser output
    # (fw_block, fw_allow, scan_detected, ...) matches correctly.
    #
    # Args:
    # rows: list of dicts from query_window()
    #
    # Returns:
    # numpy array shape (1, 11)
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
        sum(1 for r in rows if r.get("severity") == "HIGH") / total, # high_sev_ratio
    ]])


    # Load pre-trained Isolation Forest bundle from disk.
    #
    # Returns a dict {"model", "scaler", "sklearn_version", "trained_at"}
    # (v2, scaled) or a bare IsolationForest (v1 legacy, unscaled).
    # Falls back to None when no model file exists.
    #
    # The pickle is trusted local output of scripts/train_model.py —
    # keep models/ writable only by the owner. Retrain with the same
    # scikit-learn version after upgrading it; cross-version unpickling
    # may fail.
def load_model():
    import sklearn

    if MODEL_PATH.exists():
        st = MODEL_PATH.stat()
        print(f"[ML] Loading model ({st.st_size} bytes, sklearn {sklearn.__version__})",
              file=sys.stderr)
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


    # Split a v2 bundle into (clf, scaler) or legacy (clf, None).
def _unpack_bundle(model):
    if isinstance(model, dict) and "model" in model:
        return model["model"], model.get("scaler")
    return model, None


    # Run Isolation Forest prediction.
    #
    # Accepts a v2 bundle (scales features first) or a legacy v1
    # bare classifier (features used as-is).
    #
    # Args:
    # features: numpy array shape (1, 11)
    # model: bundle dict, loaded IsolationForest, or None
    #
    # Returns:
    # (anomaly_score: float 0.0-1.0, severity: str)
def detect_ml(features, model):
    if model is None:
        return 0.0, "LOW"

    clf, scaler = _unpack_bundle(model)
    if scaler is not None:
        features = scaler.transform(features)

    raw_score = clf.decision_function(features)[0]  # typically -1.0 to 1.0
    anomaly_score = float(round(1.0 - (raw_score + 1.0) / 2.0, 4))
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    if anomaly_score > 0.85:
        severity = "CRITICAL"
    elif anomaly_score > 0.7:
        severity = "HIGH"
    elif anomaly_score > 0.5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return anomaly_score, severity
