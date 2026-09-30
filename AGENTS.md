# AGENTS.md — SISKAMLAN (Sistem Keamanan LAN)

## Quick Start

```bash
# Build the C collector (required before running)
make -C collector

# Install Python dependencies
.venv/bin/pip install -r pipeline/requirements.txt

# Start Docker infrastructure (PostgreSQL + simulated devices)
docker compose -f docker/docker-compose.yml up -d

# Launch the full system (orchestrator + TUI)
.venv/bin/python run.py
```

Press `q` to quit the TUI.

## Architecture Overview

```
Docker containers (router, switch, ap, firewall) → syslog → rsyslog → data/syslog/*.log
→ C collector (log_collector) → JSON stdout → ingest.py → PostgreSQL
→ anomaly_detector.py (rules + Isolation Forest) → TUI dashboard (queries PG every 1s)
```

- **Entry point**: `run.py` launches `pipeline/orchestrator.py` (background) then `tui/app.py` (foreground)
- **Orchestrator**: tails syslog files, pipes to C collector, manages ingest + detector threads
- **Docker network**: `172.20.0.0/16`; PostgreSQL at `172.20.0.20:5432`
- **C collector**: built from `collector/src/*.c` via `collector/Makefile`
- **Python**: single virtualenv at `.venv`, dependencies in `pipeline/requirements.txt`
- **No pyproject.toml, no setup.py, no CI workflows**

## Key Commands

| Command | Purpose |
|---------|---------|
| `make -C collector` | Build C log collector binary |
| `make -C collector test` | Run 27 C unit tests |
| `.venv/bin/pip install -r pipeline/requirements.txt` | Install Python deps |
| `docker compose -f docker/docker-compose.yml up -d` | Start Docker infrastructure |
| `.venv/bin/python run.py` | Launch orchestrator + TUI |
| `.venv/bin/python train/train_model.py --window-minutes 480` | Retrain ML model |
| `.venv/bin/python pipeline/orchestrator.py` | Run pipeline only (no TUI) |
| `.venv/bin/python tui/app.py` | Run TUI only (pipeline must be running) |

## Environment & Configuration

- **`.env`** must exist (gitignored, create from `.env.example`). Contains PG credentials consumed by `db/init.py` via `load_dotenv`.
- **Default PG host**: `172.20.0.20` (Docker). For local dev without Docker, set `PGHOST=localhost` in `.env`.
- **`.env` is loaded automatically** by `db/init.py` and `orchestrator.py` — no need to call `load_dotenv` manually.
- **`.venv` is the venv path** — the project uses `.venv/` not `venv/` or `pipenv`.

## Critical Constraints

- **C collector binary must exist** at `collector/log_collector` before starting the orchestrator. If missing, orchestrator exits immediately.
- **`data/syslog/*.log` files must exist** for the orchestrator to start (populated by Docker's rsyslog container).
- **ML model is optional**: If `pipeline/models/isolation_forest.pkl` is missing, the ML layer is disabled but rules-based detection still works.
- **Training window must match detection**: `ml_engine.WINDOW_SECONDS = 30`. Train with `--window-seconds 30` (default) to match.
- **No data retention** — tables grow unbounded. Fine for demos, not long-running deployments.
- **Unix-only launcher** — `run.py` assumes `.venv/bin/python` layout.
- **`docker compose`** (v2 syntax), not `docker-compose`.

## Python Entry Points

All Python entry points add the project root to `sys.path` and load `.env` via `db/init.py`:

- `run.py` → launches orchestrator + TUI
- `pipeline/orchestrator.py` → C collector + ingest + detector threads
- `tui/app.py` → Textual dashboard (queries PG every 1s)
- `train/train_model.py` → ML training script
- `pipeline/ingest.py` → batch inserts from collector stdout
- `pipeline/anomaly_detector.py` → rules + ML detection loop
- `db/init.py` → shared DB module (`get_connection`, `insert_log_batch`, etc.)

## TUI Key Bindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/resume auto-scroll |
| `/` | Focus search bar |
| `Esc` | Clear search / dismiss modal |
| `Tab` | Cycle between panels |
| `Space` | Open security overview modal |

## Testing

- **C tests**: `make -C collector test` (builds and runs 27 unit tests in `collector/tests/test_parser.c`)
- **No Python test framework configured** — no pytest config, no `tests/` directory in pipeline/tui
- **No CI workflows** exist in `.github/`

## Important Paths

| Path | Purpose |
|------|---------|
| `collector/` | C source code, Makefile, tests |
| `collector/log_collector` | Built binary (gitignored, rebuilt via make) |
| `pipeline/` | Ingestion, anomaly detection, ML engine, orchestrator |
| `pipeline/models/isolation_forest.pkl` | Trained ML model (gitignored) |
| `pipeline/requirements.txt` | Python dependencies |
| `tui/` | Textual TUI dashboard |
| `tui/app.py` | Main TUI entry point |
| `db/init.py` | Shared database helpers |
| `train/train_model.py` | ML training script |
| `docker/docker-compose.yml` | Docker infrastructure |
| `docker/postgres/init.sql` | Database schema |
| `data/syslog/` | Syslog files from Docker containers |
| `.env` | PG credentials (gitignored, must be created) |
