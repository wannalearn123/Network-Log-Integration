# Network LAN Monitoring System

Real-time network monitoring system with automated anomaly detection. Simulates a building LAN using Docker containers, collects syslog data with a C collector, stores it in PostgreSQL, detects anomalies using rules + Isolation Forest ML, and displays everything in a terminal dashboard.

## Quick Start

```bash
# 1. Build the C collector
make -C collector

# 2. Install Python dependencies
.venv/bin/pip install -r pipeline/requirements.txt

# 3. Start Docker infrastructure (PostgreSQL + simulated devices)
docker compose -f docker/docker-compose.yml up -d

# 4. Launch everything
.venv/bin/python run.py
```

Press `q` to quit.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Docker Network (172.20.0.0/16)                          │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  router   │ │  switch   │ │    ap    │ │ firewall │   │
│  │  (syslog) │ │  (syslog) │ │ (syslog) │ │ (syslog) │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │
│       │             │            │             │          │
│       └──────┬──────┴────────────┴──────┬──────┘          │
│              ▼                          ▼                 │
│  ┌─────────────────┐      ┌──────────────────────┐      │
│  │  syslog (rsyslog)│      │  PostgreSQL           │      │
│  │  172.20.0.10     │      │  172.20.0.20:5432     │      │
│  └────────┬────────┘      └──────────▲───────────┘      │
│           │ writes .log files         │ INSERT           │
└───────────┼───────────────────────────┼──────────────────┘
            ▼                           │
┌───────────────────────────────────────┴──────────────────┐
│  Host                                                      │
│                                                            │
│  ┌──────────────┐    pipe    ┌─────────────┐              │
│  │ log_collector │ ────────→ │  ingest.py   │ ──→ PostgreSQL│
│  │ (C, reads    │  JSON      │  (Python)    │              │
│  │  syslog files)│            └─────────────┘              │
│  └──────────────┘                                          │
│                                                            │
│  ┌──────────────────┐    ┌─────────────────┐              │
│  │ anomaly_detector  │──→│  ml_engine       │              │
│  │ (rules + ML)      │    │ (Isolation Forest)│             │
│  └──────────────────┘    └─────────────────┘              │
│                                                            │
│  ┌──────────────────┐                                      │
│  │ TUI Dashboard    │  ← queries PostgreSQL every 1s      │
│  │ (Textual)        │                                      │
│  └──────────────────┘                                      │
└──────────────────────────────────────────────────────────┘
```

**Data flow:**
1. Docker containers generate simulated syslog traffic
2. rsyslog aggregates logs into per-device files under `data/syslog/`
3. `log_collector` (C) tails the files, parses syslog, outputs JSON to stdout
4. `ingest.py` reads JSON lines and batch-inserts into PostgreSQL
5. `anomaly_detector.py` queries recent logs every 15s, runs rules + ML, inserts anomalies
6. TUI dashboard queries PostgreSQL every second and displays live data

## Components

### C Log Collector (`collector/`)

Parses real-world syslog formats from Cisco, MikroTik, Ruijie, FortiGate, hostapd, iptables, and standard syslog. Outputs structured JSON with 9 fields: timestamp, hostname, facility, severity, device_type, event, src_ip, dst_ip, proto, dst_port.

```bash
make -C collector          # build
make -C collector test     # run 27 unit tests
```

### Python Pipeline (`pipeline/`)

- **orchestrator.py** — Starts the collector and ingest threads, monitors health
- **ingest.py** — Reads collector JSON output, batch-inserts into PostgreSQL
- **anomaly_detector.py** — Queries recent logs, runs rules + ML detection
- **rules_engine.py** — 4 detection rules: port scan, brute force, flood, high drop rate
- **ml_engine.py** — Isolation Forest for unsupervised anomaly scoring

### TUI Dashboard (`tui/`)

Terminal-based dashboard built with [Textual](https://textual.textualize.io/). Displays live log stream, anomaly alerts, device stats, and supports text search.

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/resume auto-scroll |
| `/` | Focus search bar |
| `Esc` | Clear search |
| `Tab` | Cycle between panels |

### ML Training (`train/`)

```bash
.venv/bin/python train/train_model.py --window-minutes 480
```

Trains an Isolation Forest on collected log data. Saves model + quantile-based severity thresholds to `pipeline/models/isolation_forest.pkl`.

## Configuration

Environment variables (set in `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PGHOST` | `172.20.0.20` | PostgreSQL host |
| `PGPORT` | `5432` | PostgreSQL port |
| `PGDATABASE` | `network_logs` | Database name |
| `PGUSER` | `monitor` | Database user |
| `PGPASSWORD` | `monitor` | Database password |
| `PGCONNECT_TIMEOUT` | `3` | Connection timeout (seconds) |

## Project Structure

```
Monitoring System/
├── run.py                  # Parent launcher (starts orchestrator + TUI)
├── .env                    # Database credentials (not committed)
├── collector/              # C log collector
│   ├── src/                # parser, syslog, devices, json_out, collector, main
│   └── tests/              # 27 unit tests
├── pipeline/               # Python ingestion + detection
│   ├── models/             # Trained ML models (.pkl)
│   └── requirements.txt    # Python dependencies
├── train/                  # ML training script
├── tui/                    # Textual TUI dashboard
│   └── widgets/            # LogStream, AnomalyPanel, StatsBar, SearchBar
├── db/                     # Database connection helpers
├── docker/                 # Docker infrastructure
│   ├── docker-compose.yml  # 6 services (syslog, postgres, router, switch, ap, firewall)
│   └── postgres/init.sql   # Schema
└── data/                   # Runtime data (syslog files, postgres volume)
```

## Known Limitations

- **No data retention** — tables grow unbounded; fine for demos, not for long-running deployments
- **No connection pooling** — TUI opens a new DB connection every second
- **Firewall is simulated** — generates fake firewall logs, does not filter traffic
- **IPv4 only** — IPv6 addresses are not parsed
- **No retrain automation** — model must be retrained manually after significant data changes
- **Unix-only launcher** — `run.py` assumes `.venv/bin/python` layout
