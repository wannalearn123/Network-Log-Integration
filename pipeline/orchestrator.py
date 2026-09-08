#!/usr/bin/env python3
# Real-time log ingestion pipeline — reads syslog, pipes through C collector, inserts into PostgreSQL.

import subprocess
import threading
import time
import signal
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.ingest import run_ingest
from pipeline.anomaly_detector import start_detector


TAIL_POLL_INTERVAL = 0.1  # 100ms
COLLECTOR_BIN = "./collector/log_collector"

running = True
_stdin_lock = threading.Lock()


    # Tail a file from the end, feed new lines to collector stdin.
def tail_file(filepath, stdin_pipe):
    with open(filepath, "r") as f:
        f.seek(0, 2)  # seek to end
        while running:
            line = f.readline()
            if line:
                try:
                    with _stdin_lock:
                        stdin_pipe.write(line.encode("utf-8"))
                        stdin_pipe.flush()
                except BrokenPipeError:
                    return
                except OSError:
                    return
            else:
                time.sleep(TAIL_POLL_INTERVAL)


def start_collector():
    proc = subprocess.Popen(
        [COLLECTOR_BIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    return proc


def signal_handler(sig, frame):
    global running
    print("\n[SHUTDOWN] Stopping pipeline...", file=sys.stderr)
    running = False


def main():
    global running

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Find log files
    log_dir = Path("data/syslog")
    log_files = sorted(log_dir.glob("*.log"))
    if not log_files:
        print("[ERROR] No log files found in data/syslog/", file=sys.stderr)
        sys.exit(1)

    # Exit if the collector binary is missing.
    if not Path(COLLECTOR_BIN).exists():
        print(f"[ERROR] Missing {COLLECTOR_BIN} — run: make -C collector", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Found {len(log_files)} log files:", file=sys.stderr)
    for f in log_files:
        print(f"[INFO]   - {f.name}", file=sys.stderr)

    # Start collector
    collector = start_collector()
    print("[INFO] C collector started", file=sys.stderr)

    # Start tail threads
    tail_threads = []
    for log_file in log_files:
        t = threading.Thread(
            target=tail_file,
            args=(str(log_file), collector.stdin),
            daemon=True,
        )
        t.start()
        tail_threads.append(t)

    # Start ingest thread
    ingest_thread = threading.Thread(
        target=run_ingest,
        args=(collector.stdout,),
        daemon=True,
    )
    ingest_thread.start()

    # Start anomaly detector thread
    detector_thread = threading.Thread(
        target=start_detector,
        args=(30,),
        daemon=True,
    )
    detector_thread.start()
    print("[INFO] Anomaly detector started", file=sys.stderr)

    # Watchdog: stop if any component dies.
    print("[INFO] Pipeline running — Ctrl+C to stop", file=sys.stderr)
    failed = False
    while running:
        if collector.poll() is not None:
            print(f"[FATAL] C collector exited ({collector.returncode}) — stopping", file=sys.stderr)
            running = False
            failed = True
            break
        if not ingest_thread.is_alive():
            print("[FATAL] Ingest thread died — stopping", file=sys.stderr)
            running = False
            failed = True
            break
        if not detector_thread.is_alive():
            print("[FATAL] Detector thread died — stopping", file=sys.stderr)
            running = False
            failed = True
            break
        time.sleep(1)

    # Cleanup
    try:
        collector.stdin.close()
    except Exception:
        pass
    try:
        if collector.poll() is None:
            collector.terminate()
        collector.wait(timeout=5)
    except Exception:
        try:
            collector.kill()
        except Exception:
            pass
    print("[INFO] Pipeline stopped", file=sys.stderr)
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
