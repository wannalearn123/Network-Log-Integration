import json
import os
import select
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.init import get_connection, insert_log_batch, insert_log_entry
import psycopg2


FLUSH_INTERVAL = 1.0  # seconds — batch is dynamic, bounded by time only
MAX_BATCH = 10000  # safety cap: drop oldest on backpressure, never grow unbounded

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

    try:
        cursor = conn.cursor()
        batch = []
        total = 0
        dropped = 0
        last_flush = time.monotonic()

        print("[INGEST] Connected to PostgreSQL", file=sys.stderr)

            # Flush batch; on failure retry row-by-row and skip poison rows.
            # Connection errors are re-raised so the watchdog stops the pipeline.
        def flush_batch():
            nonlocal total, dropped, last_flush
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
        buf = bytearray()
        bytes_read = 0
        partial_waits = 0
        malformed = 0

        def handle_line(raw_line):
            nonlocal dropped, malformed
            line = raw_line.strip()
            if not line:
                return
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                if malformed == 1 or malformed % 100 == 0:
                    print(f"[INGEST] Skipped malformed JSON line (total {malformed})",
                          file=sys.stderr)
                return
            if len(batch) >= MAX_BATCH:
                del batch[0]
                dropped += 1
                if dropped == 1 or dropped % 1000 == 0:
                    print(f"[INGEST] Backpressure: dropped {dropped} oldest rows",
                          file=sys.stderr)
            batch.append(entry)

        while running:
            try:
                ready, _, _ = select.select([fd], [], [], 1.0)
            except (OSError, ValueError):
                break

            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:  # EOF — collector closed stdout
                    if buf:
                        handle_line(bytes(buf).decode("utf-8", errors="replace"))
                        buf.clear()
                    break
                bytes_read += len(chunk)
                buf.extend(chunk)
                # Emit only complete lines; half-line stays buffered
                while True:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        break
                    raw = bytes(buf[:nl])
                    del buf[:nl + 1]
                    handle_line(raw.decode("utf-8", errors="replace"))
                if buf:
                    # Data arrived but no full line yet — don't block, re-loop
                    partial_waits += 1
            # else: select timeout — running re-checked at loop top for fast shutdown

            # Time-bounded flush — runs on data and idle paths alike
            if batch and (time.monotonic() - last_flush) >= FLUSH_INTERVAL:
                flush_batch()

        # Flush remaining
        flush_batch()

        print(f"[INGEST] Done — {total} total entries, {dropped} dropped on backpressure, "
              f"{malformed} malformed, {bytes_read} bytes, {partial_waits} partial waits",
              file=sys.stderr)
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
