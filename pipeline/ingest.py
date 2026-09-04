import json
import select
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.init import get_connection, insert_log_batch


BATCH_SIZE = 5
FLUSH_INTERVAL = 5  # seconds

running = True


    # Signal the ingest loop to exit.
def stop():
    global running
    running = False


    # Read JSON lines from collector stdout, insert into PostgreSQL.
    #
    # Single-threaded: the main loop owns the connection/cursor and
    # flushes by size OR by elapsed time (via select timeout), so no
    # lock discipline or cross-thread cursor sharing is needed.
def run_ingest(collector_stdout):
    global running

    conn = get_connection()
    cursor = conn.cursor()
    batch = []
    total = 0
    last_flush = time.monotonic()

    print("[INGEST] Connected to PostgreSQL", file=sys.stderr)

        # Flush accumulated batch to database with rollback on error.
    def flush_batch():
        nonlocal total, last_flush
        if not batch:
            last_flush = time.monotonic()
            return
        try:
            insert_log_batch(cursor, batch)
            conn.commit()
            total += len(batch)
            print(f"[INGEST] {total} entries inserted", file=sys.stderr)
        except Exception as e:
            print(f"[INGEST] Flush failed, rolled back: {e}", file=sys.stderr)
            try:
                conn.rollback()
            except Exception:
                pass
        finally:
            batch.clear()
            last_flush = time.monotonic()

    running = True
    fd = collector_stdout.fileno()

    while running:
        # Wait up to 1s for data so time-based flush still fires when idle
        try:
            ready, _, _ = select.select([fd], [], [], 1.0)
        except (OSError, ValueError):
            break

        if ready:
            raw = collector_stdout.readline()
            if not raw:  # EOF — collector closed stdout
                break
            line = raw.decode("utf-8", errors="replace").strip() if isinstance(raw, bytes) else raw.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            batch.append(entry)
            if len(batch) >= BATCH_SIZE:
                flush_batch()
        else:
            # No data — flush stale partial batch
            if batch and (time.monotonic() - last_flush) >= FLUSH_INTERVAL:
                flush_batch()

    # Flush remaining
    flush_batch()

    print(f"[INGEST] Done — {total} total entries", file=sys.stderr)
    cursor.close()
    conn.close()
