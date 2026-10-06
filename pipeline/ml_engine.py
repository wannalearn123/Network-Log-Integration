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


# --- firewall window → training feature vectors -----------------------------
# Per-traffic scoring (matches UNSW per-flow training): one vector per
# firewall row, classified individually, window verdict = max score.
def _proto_of(row):
    # collector normalizes proto (6→tcp, 17→udp); anything outside the
    # training keep-list (e.g. icmp) → 'other' to match the rare grouping
    proto = str(row.get("proto") or "other").lower()
    if proto not in ("arp", "ospf", "tcp", "udp", "unas"):
        proto = "other"
    return proto


def _row_vector(row, fw, feats, impute):
    """Feature vector for a single firewall row; ct_*/dur anchored on it."""
    src, dst = row.get("src_ip"), row.get("dst_ip")
    svc, sprt = row.get("dst_port"), row.get("src_port")
    proto = _proto_of(row)

    # dur = span of this row's flow group (src+dst+port); single-shot
    # (scan, one-packet flow) → 0.0 → attack signature.
    grp_ts = [r["timestamp"] for r in fw
              if r.get("timestamp") is not None
              and r.get("src_ip") == src
              and r.get("dst_ip") == dst
              and r.get("dst_port") == svc]
    dur = (max(grp_ts) - min(grp_ts)).total_seconds() if len(grp_ts) > 1 else 0.0

    def _n(pred):
        return float(sum(1 for r in fw if pred(r)))

    ct = {
        "40": _n(lambda r: r.get("src_ip") == src
                 and r.get("dst_port") == svc),
        "41": _n(lambda r: r.get("dst_ip") == dst
                 and r.get("dst_port") == svc),
        "42": _n(lambda r: r.get("dst_ip") == dst),
        "43": _n(lambda r: r.get("src_ip") == src),
        "44": _n(lambda r: r.get("src_ip") == src
                 and r.get("dst_port") == svc),
        "45": _n(lambda r: r.get("dst_ip") == dst
                 and r.get("src_port") == sprt),
        "46": _n(lambda r: r.get("src_ip") == src
                 and r.get("dst_ip") == dst),
    }

    vec = []
    for col in feats:
        if col == "3":                                  # dsport
            v = row.get("dst_port")
            vec.append(float(v) if v is not None else float(impute.get("3", 0.0)))
        elif col.startswith("4_"):                      # proto dummies
            vec.append(1.0 if col == "4_" + proto else 0.0)
        elif col == "6":                                # dur (seconds)
            vec.append(float(dur))
        elif col in ct:                                 # 40-46 window counters
            vec.append(ct[col])
        else:
            # No silent medians: every bundle feature must be derivable
            # from the syslog window, or training and serve have diverged.
            raise ValueError(f"feature {col!r} not derivable from syslog row — retrain first")
    return vec


def score_firewall_window(rows, window_seconds, bundle):
    """Classify each firewall row; verdict = max score.

    Returns (score, severity, detail) where detail = {"scored": n,
    "high": count >= high threshold}. Returns (0.0, "LOW", {"scored": 0,
    "high": 0}) when the window holds no firewall rows.
    """
    fw = [r for r in rows if (r.get("device_type") or "") == "firewall"]
    if not fw or bundle is None:
        return 0.0, "LOW", {"scored": 0, "high": 0}

    feats = bundle["features"]
    impute = bundle.get("impute") or {}
    X = np.array([_row_vector(r, fw, feats, impute) for r in fw], dtype=float)

    if isinstance(bundle, dict) and bundle.get("log_scaled"):
        idx = bundle.get("log_count_idx") or []
        X = X.copy()
        X[:, list(idx)] = np.log1p(np.clip(X[:, list(idx)], 0, None))
    scaler = bundle.get("scaler") if isinstance(bundle, dict) else None
    if scaler is not None:
        X = scaler.transform(X)

    clf = bundle["model"] if isinstance(bundle, dict) and "model" in bundle else bundle
    thresholds = bundle.get("thresholds") if isinstance(bundle, dict) else None
    if not thresholds:
        raise ValueError("Model bundle missing thresholds — retrain first")

    if hasattr(clf, "predict_proba"):
        scores = [max(0.0, min(1.0, round(float(s), 4)))
                  for s in clf.predict_proba(X)[:, 1]]
    else:
        k = bundle.get("sigmoid_k", 5) if isinstance(bundle, dict) else 5
        scores = []
        for raw in clf.decision_function(X):
            s = 1.0 / (1.0 + math.exp(-k * (-float(raw))))
            scores.append(max(0.0, min(1.0, round(s, 4))))

    hi = float(thresholds["high"])
    best = max(scores)
    detail = {"scored": len(scores), "high": sum(1 for s in scores if s >= hi)}
    return best, _severity(best, thresholds), detail


# --- JEV second-opinion layer (rules stay authoritative, never suppressed) ---
# Asks one typed noul per window: "Does this log window contain a network attack?"
# State is aggregate counts (rates are invisible in single lines) plus a few
# sample lines. Config via .env: ENABLE_JEV_CLASSIFIER, JEV_API_BASE,
# JEV_API_KEY, JEV_MIN_CONFIDENCE. Never raises.

import json as _json
import os as _os
import urllib.error as _urlerror
import urllib.request as _urlrequest

from pipeline.rules_engine import _identity as _jev_entity

JEV_TIMEOUT_SECONDS = 5

# One call per window, so the state is bounded by these caps rather than by
# window size. Sample lines stay few: the counts above them carry the signal.
JEV_SAMPLE_LINES = 8
JEV_SAMPLE_LINE_LEN = 160
JEV_TOP_ENTITIES = 5
JEV_MAX_STATE_CHARS = 4000

# P(attack) -> severity. Deliberately conservative: second opinion only.
JEV_P_CRITICAL = 0.85
JEV_P_HIGH = 0.65
JEV_P_MEDIUM = 0.45


def _jev_log(msg):
    print(f"[JEV] {msg}", file=sys.stderr)


def _jev_enabled():
    return _os.environ.get("ENABLE_JEV_CLASSIFIER", "").strip().lower() in (
        "1", "true", "yes")


def _jev_min_confidence():
    try:
        return float(_os.environ.get("JEV_MIN_CONFIDENCE", "0.6"))
    except ValueError:
        return 0.6


def _jev_sample_line(row):
    """One representative log line, for context under the counts."""
    raw = row.get("raw_line")
    if raw:
        return str(raw).strip()[:JEV_SAMPLE_LINE_LEN]
    ts = row.get("timestamp")
    time_str = str(ts)[11:19] if ts else "--:--:--"
    device = row.get("device_type") or "?"
    event = row.get("event") or "?"
    detail = (row.get("src_ip") or row.get("client_mac")
              or row.get("mac") or row.get("entity") or "")
    port = row.get("dst_port")
    if port:
        detail = f"{detail}:{port}" if detail else f":{port}"
    return f"{time_str} {device} {event} {detail}".strip()[:JEV_SAMPLE_LINE_LEN]


def build_window_state(rows, window_seconds=WINDOW_SECONDS, detail=None):
    """Aggregate the log window into a text state for the model.

    Leads with the rates (event counts, per-entity counts, unique-port
    counts) because those are what attack signatures are made of, then adds a
    few sample lines. Returns "" when there is nothing to judge.
    """
    if not rows:
        return ""

    window_seconds = max(1, int(window_seconds or WINDOW_SECONDS))
    rate = len(rows) / window_seconds

    event_counts = {}
    device_counts = {}
    per_entity = {}
    for row in rows:
        event = (row.get("event") or "?").upper()
        event_counts[event] = event_counts.get(event, 0) + 1
        device = row.get("device_type") or "?"
        device_counts[device] = device_counts.get(device, 0) + 1
        entity = _jev_entity(row)
        if entity:
            stats = per_entity.setdefault(
                entity, {"count": 0, "events": {}, "ports": set()})
            stats["count"] += 1
            stats["events"][event] = stats["events"].get(event, 0) + 1
            port = row.get("dst_port")
            if port is not None:
                stats["ports"].add(port)

    def _tally(counts, limit=None):
        items = sorted(counts.items(), key=lambda kv: -kv[1])
        if limit:
            items = items[:limit]
        return ", ".join(f"{k}={v}" for k, v in items)

    lines = [
        f"WINDOW SUMMARY ({window_seconds}s): {len(rows)} events "
        f"({rate:.1f}/s), {len(device_counts)} devices, "
        f"{len(per_entity)} attributed entities",
        f"EVENT COUNTS: {_tally(event_counts)}",
        f"DEVICE COUNTS: {_tally(device_counts)}",
        "TOP ENTITIES (count, event breakdown, unique dst ports):",
    ]

    for entity, stats in sorted(per_entity.items(),
                                key=lambda kv: -kv[1]["count"])[:JEV_TOP_ENTITIES]:
        lines.append(
            f"  {entity}: {stats['count']} events, "
            f"[{_tally(stats['events'], 3)}], "
            f"{len(stats['ports'])} unique dst ports")

    lines.append("SAMPLE LOG LINES:")
    # Most recent samples, skipping the aggregate noise (NAT bookkeeping)
    # which would otherwise crowd out the interesting traffic.
    interesting = [r for r in rows if (r.get("event") or "") not in
                   ("nat_conntrack", "nat_event", "signal_report")]
    for row in interesting[-JEV_SAMPLE_LINES:]:
        lines.append("  " + _jev_sample_line(row))

    state = "\n".join(lines)
    if len(state) > JEV_MAX_STATE_CHARS:
        state = state[:JEV_MAX_STATE_CHARS]
    return state


def jev_severity(probability, confidence):
    """Map P(attack) to a severity, or None when the answer is untrusted."""
    if probability is None:
        return None
    if confidence is not None and confidence < _jev_min_confidence():
        return None
    if probability >= JEV_P_CRITICAL:
        return "CRITICAL"
    if probability >= JEV_P_HIGH:
        return "HIGH"
    if probability >= JEV_P_MEDIUM:
        return "MEDIUM"
    return None


def _jev_extract(answers):
    """Pull P(true) and confidence out of the typed answer object."""
    if not isinstance(answers, dict):
        return None, None
    for key in ("attack", "malicious"):
        ans = answers.get(key)
        if isinstance(ans, dict) and ans.get("type") == "noul":
            return ans.get("noul"), ans.get("confidence")
    return None, None


def _jev_endpoint():
    """Resolve the configured endpoint, or None when unusable."""
    endpoint = _os.environ.get("JEV_API_BASE", "").strip().rstrip("/")
    if not endpoint:
        return None
    if not endpoint.startswith(("http://", "https://")):
        endpoint = f"http://{endpoint}"
    return endpoint


def _jev_headers():
    headers = {"Content-Type": "application/json"}
    api_key = _os.environ.get("JEV_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def classify_window_jev(rows, window_seconds=WINDOW_SECONDS):
    """Ask the model whether this window contains an attack.

    One typed question over the aggregate state; the verdict is that single
    answer, so there is no per-row fan-out and no per-row latency cost.

    Returns {"severity", "probability", "confidence", "model", "detail"} or
    None when disabled, not configured, unreachable, or undecided. Never raises.
    """
    if not _jev_enabled():
        return None
    endpoint = _jev_endpoint()
    if not endpoint:
        _jev_log("JEV_API_BASE not set — ML layer skipped")
        return None

    state = build_window_state(rows, window_seconds)
    if not state:
        return None

    payload = _json.dumps({
        "state": state,
        "questions": {"attack": {
            "type": "noul",
            "instructions": "Does this log window contain a network attack?",
        }},
    }).encode("utf-8")

    req = _urlrequest.Request(endpoint, data=payload, headers=_jev_headers())
    try:
        with _urlrequest.urlopen(req, timeout=JEV_TIMEOUT_SECONDS) as resp:
            data = _json.loads(resp.read().decode("utf-8", "replace"))
    except _urlerror.HTTPError as e:
        _jev_log(f"HTTP {e.code}: "
                 f"{e.read().decode('utf-8', 'replace')[:200]}")
        return None
    except Exception as e:
        _jev_log(f"request failed ({e}) — ML skipped, rules unaffected")
        return None

    probability, confidence = _jev_extract(data.get("answers"))
    if probability is None:
        _jev_log(f"no noul answer in response: {str(data)[:200]}")
        return None

    severity = jev_severity(probability, confidence)
    if severity is None:
        _jev_log(f"P={probability:.3f} conf={confidence} below thresholds — ignored")
        return None

    entity_counts = {}
    for row in rows:
        entity = _jev_entity(row)
        if entity:
            entity_counts[entity] = entity_counts.get(entity, 0) + 1
    top = max(entity_counts, key=entity_counts.get) if entity_counts else None

    return {
        "severity": severity,
        "probability": probability,
        "confidence": confidence,
        "model": data.get("model", "unknown"),
        "detail": {
            "events": len(rows),
            "entities": len(entity_counts),
            "top_entity": top,
            "top_entity_events": entity_counts.get(top, 0) if top else 0,
            "state_chars": len(state),
        },
    }
