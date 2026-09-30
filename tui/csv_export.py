# CSV export — dump the dashboard's current view (respects the active
# search filter) to timestamped files under data/exports/.
#
# Stdlib csv only — no new dependencies. Never raises: a failed export
# must not take the TUI down.

import csv
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPORT_DIR = PROJECT_ROOT / "data" / "exports"

# Column order for the log export. Keys are LogStream._rows detail keys.
LOG_COLUMNS = [
    "time", "device", "type", "event", "src_ip", "dst_ip",
    "entity", "proto", "port", "src_port", "action",
]

# Column order for the anomaly export. Keys are AnomalyPanel._rows keys.
ANOMALY_COLUMNS = [
    "time", "severity", "score", "description",
]


def plan_export(stamp=None, directory=None):
    """Return (log_path, anom_path) without touching the filesystem.

    The TUI confirmation modal shows these names, so the caller must
    reuse the same stamp when it finally calls export_view().
    """
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(directory) if directory else EXPORT_DIR
    return out_dir / f"logs-{stamp}.csv", out_dir / f"anomalies-{stamp}.csv"


def _log(msg):
    print(f"[EXPORT] {msg}", file=sys.stderr)


def _write(path, columns, rows):
    # utf-8-sig so Excel opens the file without mangling accents.
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in columns})
    return len(rows)


def export_view(log_rows, anomaly_rows, stamp=None, directory=None):
    """Write logs + anomalies as two CSVs. Returns (log_path, anom_path, n)."""
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(directory) if directory else EXPORT_DIR
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = out_dir / f"logs-{stamp}.csv"
        anom_path = out_dir / f"anomalies-{stamp}.csv"
        n_logs = _write(log_path, LOG_COLUMNS, log_rows or [])
        n_anoms = _write(anom_path, ANOMALY_COLUMNS, anomaly_rows or [])
    except OSError as e:
        _log(f"export failed: {e}")
        return None
    _log(f"wrote {n_logs} logs -> {log_path}")
    _log(f"wrote {n_anoms} anomalies -> {anom_path}")
    return log_path, anom_path, n_logs + n_anoms
