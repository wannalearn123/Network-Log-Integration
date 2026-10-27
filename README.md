# SISKAMLAN — LAN Security Monitoring

Rules-based syslog monitoring: a Go parser, PostgreSQL storage, a Bubble Tea
terminal dashboard, Docker device simulators, and optional Telegram alerts.

## Setup

Requires Linux, Go 1.24+ and Docker Compose v2.

```bash
cp .env.example .env
make build                 # produces ./siskamlan
docker compose up -d --build
./siskamlan                # pipeline + dashboard in one process
```

Database credentials are read from `.env`; the sample host `172.20.0.20` is the
PostgreSQL container on Linux. PostgreSQL stores its data in `data/pgdata`.

## Architecture

```text
device simulators → rsyslog → data/syslog/*.log
  → tailer → parser → ingest → PostgreSQL
  → rules engine → anomalies → TUI / optional Telegram
```

One binary runs everything: the tailer, ingester and detector run as
goroutines while the dashboard owns the terminal. The tailer discovers new
files and handles rotation/truncation. Existing files start at EOF; ingestion
is live-only, with offsets persisted atomically so restarts resume mid-file.

The detector checks a 30-second window every 15 seconds. Rules cover port
scans, authentication failures, deauth storms, log floods, firewall drops, MAC
flaps, STP instability and route churn. Cooldowns merge repeats per type/entity
and reset on process restart. Rules have no probabilistic score.

## Configuration

### `.env`

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

Retention deletes old records hourly while the detector runs. Telegram requires
`TELEGRAM_BOT_TOKEN` and comma-separated `TELEGRAM_CHAT_ID`. Repeated merged
anomalies do not re-alert.

### `config/rules.yaml`

Detection rules are data, not code. Each rule filters rows over a window,
groups them, and compares a count rate against a threshold. Edit the file
directly or use the dashboard's rules editor; changes apply within 15 seconds
with no restart.

```yaml
version: 1
window_seconds: 30
rules:
  - name: PORT_SCAN
    severity: HIGH
    rate: 0.4                  # events per second (>=12 in 30s)
    group_by: [src_ip]
    count: distinct
    distinct_on: dst_port
    when:
      all:
        - {field: src_ip, op: exists}
        - {field: dst_port, op: exists}
    description: "Port scan from {entity} — {count} ports in {window}s"
```

Conditions nest with `all` / `any` / `not`. Operators: `eq`, `ne`, `contains`,
`icontains`, `contains_any`, `prefix`, `suffix`, `regex`, `in`, `not_in`,
`exists`, `not_exists`, `gt`, `gte`, `lt`, `lte`. `$identity` (AP→client MAC,
switch→MAC, else source IP) and `$mac` are synthetic group fields. An invalid
edit is rejected and the previous rules keep running.

### `config/parsers.yaml`

New log types are supported without rebuilding. A device profile matches by
hostname and maps keywords onto structured columns.

```yaml
version: 1
devices:
  - name: fortigate
    hostname_match: ['^firewall', '^lab-firewall']
    device_type: firewall
    fields:
      - {target: src_ip,   strategy: kv, key: src}
      - {target: dst_port, strategy: kv, key: dpt, type: int}
      - {target: action,   strategy: word_map, source: action,
         map: {accept: allow, drop: deny}}
    events:
      - {event: fw_block, contains: ['act=deny', 'act=drop']}
```

Strategies: `kv`, `regex`, `word_map`, `positional`. Hosts that match no
profile keep using the built-in parser, so adding a profile never changes
existing behaviour. Changes apply within one second.

## Dashboard

```text
./siskamlan          # pipeline + dashboard
./siskamlan run      # pipeline only (headless)
./siskamlan tui      # dashboard only
```

| Key | Action |
|---|---|
| `q` | quit |
| `p` | pause / resume live refresh |
| `/` | filter host, event, IP, MAC, SSID |
| `↑` `↓` / `j` `k` | scroll the focused pane |
| `tab` | switch focus between logs and anomalies |
| `R` | rules editor |
| `P` | parser editor |
| `?` | help |

The rules editor supports add, edit, toggle, delete and **preview**: pressing
`p` dry-runs the rule against the last five minutes and reports how often it
would have fired. The parser editor's `i` key samples recent raw lines, lists
the `key=value` tokens it finds with a suggested target column, and builds the
assignment for you.

## Verification

```bash
make build
make test      # Go unit + integration tests
make vet
```

Go must not be invoked as `go build ./...` at the repository root: the
recursive pattern walks `data/pgdata`, which the PostgreSQL container owns with
mode 0700. The Makefile targets scope to `./cmd/...` and `./internal/...`.

PostgreSQL integration tests skip automatically when the database is
unreachable. Two oracle fixtures pin behaviour to the original implementation:
`internal/parser/testdata/golden.jsonl` (5,180 sample lines parsed identically
by the former C collector) and `internal/rules/testdata/python_hits.txt`
(detections produced by the former Python engine).

## Limitations

- Simulators generate logs; they are not production routers/firewalls.
- File offsets and cooldowns are persisted across restarts.
- UDP syslog and bounded ingest batches can lose data under load; offsets are
  persisted atomically, but records already buffered at an unclean kill may repeat.
- Timestamp inference for traditional syslog assumes current year and UTC.
- IPv6 and full RFC 5424 parsing are not supported.
- Telegram delivery is queued with bounded retries and may drop alerts when full.
- Database schema is initialized only for a fresh volume; future schema changes
  require explicit migrations rather than recreating the volume.

## Layout

`cmd/siskamlan/`: entrypoint · `internal/parser/`: syslog parsing + config ·
`internal/rules/`: detection engine · `internal/pipeline/`: tailer, ingest,
detector, alerts · `internal/store/`: PostgreSQL · `internal/tui/`: dashboard ·
`config/`: editable rules and parser definitions · `docker/`: images/schema ·
`data/syslog/`: collected logs.
