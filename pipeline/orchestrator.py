#!/usr/bin/env python3
"""Supervise collector, rotation-aware file tails, ingest and detection."""
import os
import signal
import subprocess
import sys
import threading
import json
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.ingest import run_ingest
from pipeline.anomaly_detector import start_detector


def _load_offsets(state_path):
    try:
        return json.loads(state_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save_offsets(state_path, offsets):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="offsets-", dir=state_path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(offsets, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, state_path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass


def tail_files(directory, pipe, stop, state_path=None):
    state_path = state_path or directory.parent / ".pipeline" / "offsets.json"
    streams = {}
    pending = {}
    discarding = set()
    offsets = _load_offsets(state_path)
    initial = set(directory.glob("*.log"))
    last_save = 0.0
    try:
        while not stop.is_set():
            for path in directory.glob("*.log"):
                try:
                    stat = path.stat()
                    stream = streams.get(path)
                    if stream and os.fstat(stream.fileno()).st_ino != stat.st_ino:
                        stream.close()
                        del streams[path]
                        pending.pop(path, None)
                        stream = None
                    if stream is None:
                        stream = path.open("rb")
                        streams[path] = stream
                        key = str(path.resolve())
                        saved = offsets.get(key, {})
                        if saved.get("inode") == stat.st_ino and 0 <= saved.get("offset", -1) <= stat.st_size:
                            stream.seek(saved["offset"])
                        elif path in initial and not saved:
                            stream.seek(0, 2)
                        initial.discard(path)
                    if stat.st_size < stream.tell():
                        stream.seek(0)
                        pending.pop(path, None)
                    # Bound each pass so one busy device cannot starve the others.
                    chunk = stream.read(65536)
                    data = pending.get(path, b"") + chunk
                    if path in discarding:
                        boundary = data.find(b"\n")
                        if boundary < 0:
                            pending[path] = b""
                            continue
                        data = data[boundary + 1:]
                        discarding.remove(path)
                    end = data.rfind(b"\n")
                    if end >= 0:
                        pipe.write(data[:end + 1])
                        pipe.flush()
                        data = data[end + 1:]
                    pending[path] = data
                    offsets[str(path.resolve())] = {
                        "inode": stat.st_ino,
                        "offset": stream.tell() - len(data),
                    }
                    if len(data) > 1024 * 1024:
                        print(f"[TAIL] Dropped oversized partial line in {path.name}", file=sys.stderr)
                        pending[path] = b""
                        discarding.add(path)
                except FileNotFoundError:
                    continue
            if time.monotonic() - last_save >= 1:
                _save_offsets(state_path, offsets)
                last_save = time.monotonic()
            stop.wait(0.1)
    finally:
        _save_offsets(state_path, offsets)
        for stream in streams.values():
            stream.close()


def main():
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    collector_path = ROOT / "collector/log_collector"
    if not collector_path.exists():
        raise SystemExit("Build collector first: make -C collector")
    directory = ROOT / "data/syslog"
    directory.mkdir(parents=True, exist_ok=True)
    collector = subprocess.Popen([str(collector_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # Ingest drains to EOF during shutdown so committed batches are not abandoned.
    workers = [
        threading.Thread(target=tail_files, args=(directory, collector.stdin, stop), name="tail"),
        threading.Thread(target=run_ingest, args=(collector.stdout,), name="ingest"),
        threading.Thread(target=start_detector, kwargs={"stop_event": stop}, name="detector"),
    ]
    for worker in workers:
        worker.daemon = True
        worker.start()
    failed = False
    try:
        while not stop.wait(0.5):
            if collector.poll() is not None or any(not w.is_alive() for w in workers):
                print("[FATAL] Pipeline worker exited", file=sys.stderr)
                failed = True
                break
    finally:
        stop.set()
        workers[0].join(timeout=2)
        if workers[0].is_alive():
            collector.terminate()  # Release a writer blocked by a failed ingest.
        else:
            collector.stdin.close()
        try:
            collector.wait(timeout=5)
        except subprocess.TimeoutExpired:
            collector.kill()
            collector.wait()
        for worker in workers:
            worker.join(timeout=2)
        collector.stdout.close()
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
