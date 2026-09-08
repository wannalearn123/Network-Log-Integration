import json
import select
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.init import get_connection, insert_log_batch, insert_log_entry
import psycopg2


BATCH_SIZE = 5
FLUSH_INTERVAL = 5  # seconds

running = True


    # Signal the ingest loop to exit.
def stop():
    global running
    running = False


    # Read JSON lines from collector stdout, insert into PostgreSQL.
def run_ingest(collector_stdout):
    global running

    try:
        conn = get_connection()
    except Exception as e:
        print(f"[INGEST] FATAL: PostgreSQL unreachable: {e}", file=sys.stderr)
        raise
    cursor = conn.cursor()
    batch = []
    total = 0
    last_flush = time.monotonic()

    print("[INGEST] Connected to PostgreSQL", file=sys.stderr)

        # Flush batch; on failure retry row-by-row and skip poison rows.
        # Connection errors are re-raised so the watchdog stops the pipeline.
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
            batch.clear()
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        except Exception as e:
            print(f"[INGEST] Batch failed ({e}) — retrying row-by-row", file=sys.stderr)
            try:
                conn.rollback()
            except Exception:
                pass
            ok = 0
            skipped = 0
            for entry in batch:
                try:
                    insert_log_entry(cursor, entry)
                    conn.commit()
                    ok += 1
                except (psycopg2.OperationalError, psycopg2.InterfaceError):
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    raise
                except Exception as row_e:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    skipped += 1
                    print(f"[INGEST] Skipped poison row: {row_e}", file=sys.stderr)
            total += ok
            if skipped:
                print(f"[INGEST] Dropped {skipped} poison rows, kept {ok}", file=sys.stderr)
            else:
                print(f"[INGEST] {total} entries inserted", file=sys.stderr)
            batch.clear()
        finally:
            last_flush = time.monotonic()

    running = True
    fd = collector_stdout.fileno()

    while running:
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
