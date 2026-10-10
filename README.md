# SISKAMLAN — LAN Security Monitoring

Rules-based syslog monitoring with a C parser, PostgreSQL storage, Textual
dashboard, Docker device simulators, and optional Telegram alerts.

## Setup

Requires Linux, Python 3.12+, GCC/make and Docker Compose v2.

```bash
python3 -m venv .venv
.venv/bin/pip install -r pipeline/requirements.txt
cp .env.example .env
make -C collector
docker compose up -d --build
.venv/bin/python run.py
```

An existing `venv/` also works: activate it or launch with `venv/bin/python`.
The launcher uses the interpreter running it. Database credentials are read
from `.env`; the sample host `172.20.0.20` is the PostgreSQL container on Linux.
PostgreSQL uses the Compose named volume `pgdata`.

## Architecture

```text
device simulators → rsyslog → data/syslog/*.log
  → Python file tailer → C collector → JSON → ingest → PostgreSQL
  → rules detector → anomalies → TUI / optional Telegram
```

The tailer discovers new files and handles rotation/truncation. Existing files
start at EOF; ingestion is live-only, with no durable replay/checkpoint guarantee.
The detector checks a 30-second window every 15 seconds. Rules cover port scans,
authentication failures, deauth storms, log floods, firewall drops, MAC flaps,
STP instability and route churn. Cooldowns merge repeats per type/entity and
reset on process restart. Rules have no probabilistic score.

ML experiments were dropped from the supported tree because their training
features did not match the live syslog feature contract. See `train/README.md`
for the requirements before reintroducing a validated model.

## Configuration

See `.env.example`. Key settings:

| Variable | Default | Purpose |
|---|---|---|
| PGHOST | localhost in code; 172.20.0.20 in example | PostgreSQL host |
| PGPORT | 5432 | PostgreSQL port |
| PGDATABASE / PGUSER | network_logs / monitor | Database and user |
| PGPASSWORD | monitor | Database password |
| PGCONNECT_TIMEOUT | 3 | Connect timeout in seconds |
| LOG_RETENTION_DAYS | 7 | Log retention; 0 disables |
| ANOMALY_RETENTION_DAYS | 30 | Anomaly retention; 0 disables |
| NOTIFY_TELEGRAM | off | Enable fresh-anomaly alerts |
| NOTIFY_MIN_SEVERITY | HIGH | Minimum alert severity |

Retention deletes old records hourly while the detector runs. Configure it before
starting against an existing database. Telegram requires `TELEGRAM_BOT_TOKEN`
and comma-separated `TELEGRAM_CHAT_ID`. Repeated merged anomalies do not re-alert.

## Dashboard

`q`: quit · `p`: pause · `/`: search · `Esc`: dismiss · `Tab`: focus next panel ·
`Enter`: details · `Space`: overview · `e`: export visible rows · `i`: about.

Log/anomaly views refresh every second; totals refresh every 15 seconds.
CSV confirmation captures a snapshot of the current view.

## Verification

```bash
make -C collector test
make -C collector asan
.venv/bin/python -m unittest discover -s tests -v
docker compose config --quiet
```

Run pipeline alone with `python pipeline/orchestrator.py`, or dashboard alone
with `python tui/app.py`. Startup retries PostgreSQL for a bounded period;
subsequent DB connection failure stops the pipeline and is surfaced by the launcher.

For an existing database, apply the idempotent constraint migration:

```bash
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < db/migrations/001_constraints.sql
```

This preserves historical rows and checks new writes. Fresh volumes get these
constraints automatically. No volume reset is needed.

## Follow-up plan

1. Persist file offsets and anomaly cooldowns for restart-safe processing.
2. Move database queries into a dashboard worker and update tables by stable IDs.
3. Queue Telegram alerts independently of detection; add delivery retry metrics.
4. Add retention partitioning and measured query/index tuning if volume warrants it.
5. Validate parser behavior on deployment-specific syslog formats and add fuzzing.
6. Promote ML only after the evaluation and feature-contract work in `train/README.md`.

## Limitations

- Simulators generate logs; they are not production routers/firewalls.
- File offsets and cooldowns are persisted across restarts.
- UDP syslog and bounded ingest batches can lose data under load; offsets are
  persisted atomically, but records already buffered at an unclean kill may repeat.
- Timestamp inference for traditional syslog assumes current year and UTC.
- IPv6 and full RFC 5424 parsing are not supported.
- Dashboard DB calls run in a background worker; slow queries can still delay updates.
- Telegram delivery is queued with bounded retries and may drop alerts when full.
- Database schema is initialized only for a fresh volume; future schema changes
  require explicit migrations rather than recreating the volume.

## Layout

`collector/`: C parser/tests · `pipeline/`: ingestion/detection/alerts ·
`db/`: database helpers · `tui/`: dashboard · `docker/`: images/schema ·
`docker-compose.yml`: services · `train/`: ML decision record · `tests/`: Python regressions.
