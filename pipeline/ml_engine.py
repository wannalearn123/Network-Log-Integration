# ML scoring engine — neutral shell.

import math

import numpy as np
import pickle
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "models" / "model_rf.pkl"

# Detector cadence contract (window verdict policy), not a feature parameter.
WINDOW_SECONDS = 30


# Load a model bundle from disk. Returns dict bundle or None.
def load_model(path=None, expected_window_seconds=None):
    import sklearn

    model_path = Path(path) if path else MODEL_PATH
    if not model_path.exists():
        return None
    st = model_path.stat()
    print(f"[ML] Loading model ({st.st_size} bytes, sklearn {sklearn.__version__})",
          file=sys.stderr)
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)

    if isinstance(bundle, dict):
        trained_window = bundle.get("window_seconds")
        if (expected_window_seconds is not None
                and trained_window is not None
                and int(trained_window) != int(expected_window_seconds)):
            print(f"[ML] Window mismatch: model trained on {trained_window}s, "
                  f"detector uses {expected_window_seconds}s — ML disabled",
                  file=sys.stderr)
            return None
        saved_sklearn = bundle.get("sklearn_version")
        if saved_sklearn and saved_sklearn != sklearn.__version__:
            print(f"[ML] sklearn version mismatch: model={saved_sklearn} "
                  f"runtime={
                      sklearn.__version__} — continuing, retrain recommended",
                  file=sys.stderr)
    return bundle


def _severity(score, thresholds):
    s = float(score)
    if s >= float(thresholds["critical"]):
        return "CRITICAL"
    if s >= float(thresholds["high"]):
        return "HIGH"
    if s >= float(thresholds["medium"]):
        return "MEDIUM"
    return "LOW"


# Score a feature vector. Returns (score 0.0-1.0, severity).
# Supervised bundles use P(anomaly); legacy Isolation Forest bundles use
# the negated-sigmoid of decision_function. Thresholds always come from
# the bundle — the engine calibrates nothing.
def detect_ml(features, model):
    if model is None:
        return 0.0, "LOW"

    if isinstance(model, dict) and "model" in model:
        clf = model["model"]
        thresholds = model.get("thresholds")
        scaler = model.get("scaler")
    else:
        clf, thresholds, scaler = model, None, None
    if not thresholds:
        raise ValueError("Model bundle missing thresholds — retrain first")

    X = np.asarray(features, dtype=float)
    if isinstance(model, dict) and model.get("log_scaled"):
        idx = model.get("log_count_idx") or []
        X = X.copy()
        X[:, list(idx)] = np.log1p(np.clip(X[:, list(idx)], 0, None))
    if scaler is not None:
        X = scaler.transform(X)

    if hasattr(clf, "predict_proba"):
        score = float(clf.predict_proba(X)[0, 1])
    else:
        # Legacy Isolation Forest path (higher decision_function = normal).
        k = model.get("sigmoid_k", 5) if isinstance(model, dict) else 5
        raw = float(clf.decision_function(X)[0])
        score = 1.0 / (1.0 + math.exp(-k * (-raw)))
    score = max(0.0, min(1.0, round(score, 4)))
    return score, _severity(score, thresholds)


# --- firewall window → training feature vector ------------------------------
# Called by anomaly_detector with the rows of one detection window.
# Returns np.ndarray shape (1, 41) in bundle['features'] order, or None
# when the window holds no firewall rows (skip scoring — never fabricate
# a vector from empty data).
def extract_features(rows, window_seconds, bundle):
    fw = [r for r in rows if (r.get("device_type") or "") == "firewall"]
    if not fw:
        return None

    feats = bundle["features"]
    impute = bundle.get("impute") or {}

    def _mode(vals):
        vals = [v for v in vals if v is not None and v != ""]
        if not vals:
            return None
        return max(set(vals), key=vals.count)

    # --- direct fields (window mode) ---
    dst_port = _mode([r.get("dst_port") for r in fw])

    # collector normalizes proto (6→tcp, 17→udp); anything outside the
    # training keep-list (e.g. icmp) → 'other' to match the rare grouping
    proto = str(_mode([r.get("proto") for r in fw]) or "other").lower()
    if proto not in ("arp", "ospf", "tcp", "udp", "unas"):
        proto = "other"

    # approximate tcp_flags → UNSW state (current firewall lines carry no
    # flags, so this resolves to 'other' until flag-bearing lines exist)
    flags = str(_mode([r.get("tcp_flags") for r in fw]) or "").upper()
    if "SYN" in flags and "ACK" in flags:
        state = "CON"
    elif "SYN" in flags:
        state = "REQ"
    elif "FIN" in flags:
        state = "FIN"
    else:
        state = "other"

    # --- window counters: dur + ct_* family ---
    ts = [r["timestamp"] for r in fw if r.get("timestamp") is not None]
    dur = (max(ts) - min(ts)).total_seconds() if len(ts) > 1 else 0.0

    ref_src = _mode([r.get("src_ip") for r in fw])
    ref_dst = _mode([r.get("dst_ip") for r in fw])
    ref_svc = _mode([r.get("dst_port") for r in fw])   # "service" = dst port
    ref_sprt = _mode([r.get("src_port") for r in fw])

    def _n(pred):
        return float(sum(1 for r in fw if pred(r)))

    ct = {
        "40": _n(lambda r: r.get("src_ip") == ref_src
                 and r.get("dst_port") == ref_svc),
        "41": _n(lambda r: r.get("dst_ip") == ref_dst
                 and r.get("dst_port") == ref_svc),
        "42": _n(lambda r: r.get("dst_ip") == ref_dst),
        "43": _n(lambda r: r.get("src_ip") == ref_src),
        "44": _n(lambda r: r.get("src_ip") == ref_src
                 and r.get("dst_port") == ref_svc),
        "45": _n(lambda r: r.get("dst_ip") == ref_dst
                 and r.get("src_port") == ref_sprt),
        "46": _n(lambda r: r.get("src_ip") == ref_src
                 and r.get("dst_ip") == ref_dst),
    }

    # --- assemble in exact training order ---
    vec = []
    for col in feats:
        if col == "3":                                  # dsport
            v = dst_port if dst_port is not None else impute.get("3", 0.0)
            vec.append(float(v))
        elif col.startswith("4_"):                      # proto dummies
            vec.append(1.0 if col == "4_" + proto else 0.0)
        elif col.startswith("5_"):                      # state dummies
            vec.append(1.0 if col == "5_" + state else 0.0)
        elif col == "6":                                # dur (seconds)
            vec.append(float(dur))
        elif col in ct:                                 # 40-46 window counters
            vec.append(ct[col])
        else:                                           # non-derivable → train median
            vec.append(float(impute.get(col, 0.0)))
    return np.array([vec], dtype=float)
