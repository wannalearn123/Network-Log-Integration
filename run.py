#!/usr/bin/env python3
# SISKAMLAN — Parent Launcher

import subprocess
import sys
import time
import signal
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
VENV_PYTHON = sys.executable

orchestrator_proc = None
tui_proc = None


def cleanup(sig=None, frame=None):
    print("\n[LAUNCHER] Shutting down...", file=sys.stderr)
    if tui_proc and tui_proc.poll() is None:
        tui_proc.terminate()
        try:
            tui_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tui_proc.kill()
            tui_proc.wait()
    if orchestrator_proc and orchestrator_proc.poll() is None:
        orchestrator_proc.terminate()
        try:
            orchestrator_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            print("[LAUNCHER] Orchestrator did not exit — killing", file=sys.stderr)
            orchestrator_proc.kill()
            orchestrator_proc.wait()
    print("[LAUNCHER] Stopped", file=sys.stderr)
    if sig is not None:
        sys.exit(128 + sig)


def main():
    global orchestrator_proc, tui_proc

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("=" * 50, file=sys.stderr)
    print("  SISKAMLAN", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    # Start orchestrator in background (logs to file so TUI stays clean)
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    orch_log = open(log_dir / "orchestrator.log", "a")
    print("[LAUNCHER] Starting pipeline orchestrator...", file=sys.stderr)
    orchestrator_proc = subprocess.Popen(
        [str(VENV_PYTHON), str(PROJECT_ROOT / "pipeline" / "orchestrator.py")],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=orch_log,
    )
    orch_log.close()

    # Wait for pipeline to initialize
    print("[LAUNCHER] Waiting for pipeline to initialize (3s)...", file=sys.stderr)
    time.sleep(3)

    # Check orchestrator is still running
    if orchestrator_proc.poll() is not None:
        print(
            "[LAUNCHER] ERROR: Orchestrator crashed! Check logs/orchestrator.log.", file=sys.stderr)
        sys.exit(1)

    print("[LAUNCHER] Pipeline running — launching TUI dashboard", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    # Launch TUI in foreground (blocks until user quits)
    try:
        tui_proc = subprocess.Popen(
            [str(VENV_PYTHON), str(PROJECT_ROOT / "tui" / "app.py")],
            cwd=str(PROJECT_ROOT),
        )
        while tui_proc.poll() is None:
            if orchestrator_proc.poll() is not None:
                raise RuntimeError("Pipeline stopped; see logs/orchestrator.log")
            time.sleep(0.2)
        if tui_proc.returncode:
            raise SystemExit(tui_proc.returncode)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()
