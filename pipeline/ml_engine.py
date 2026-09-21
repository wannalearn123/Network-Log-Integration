# ML scoring engine — neutral shell.

import math

import numpy as np
import pickle
import sys
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / \
    "models" / "isolation_forest.pkl"

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
