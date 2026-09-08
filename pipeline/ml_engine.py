# ML-based anomaly detection engine — Isolation Forest for unsupervised outlier detection.

import numpy as np
import pickle
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "models" / "isolation_forest.pkl"


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
    # Retrain with matching sklearn version after upgrades.
def load_model():
    import sklearn

    if MODEL_PATH.exists():
        st = MODEL_PATH.stat()
        print(f"[ML] Loading model ({st.st_size} bytes, sklearn {sklearn.__version__})",
              file=sys.stderr)
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


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

    raw_score = clf.decision_function(features)[0]  # typically -1.0 to 1.0
    anomaly_score = float(round(1.0 - (raw_score + 1.0) / 2.0, 4))
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
