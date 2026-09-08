#!/usr/bin/env python3
# Network LAN Monitor — Parent Launcher

import subprocess
import sys
import time
import signal
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
VENV_PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"

orchestrator_proc = None


def cleanup(sig=None, frame=None):
    global orchestrator_proc
    print("\n[LAUNCHER] Shutting down...", file=sys.stderr)
    if orchestrator_proc and orchestrator_proc.poll() is None:
        orchestrator_proc.terminate()
        try:
            orchestrator_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("[LAUNCHER] Orchestrator did not exit — killing", file=sys.stderr)
            orchestrator_proc.kill()
            orchestrator_proc.wait()
    print("[LAUNCHER] Stopped", file=sys.stderr)
    sys.exit(0)


def main():
    global orchestrator_proc

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("=" * 50, file=sys.stderr)
    print("  Network LAN Monitor", file=sys.stderr)
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
        tui_proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()
