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
only `TELEGRAM_BOT_TOKEN`; chats are approved at runtime. Repeated merged
anomalies do not re-alert.

#### Telegram access

Access is granted per chat, not by a fixed chat ID list:

1. A new chat sends `/start` to the bot. The bot asks for approval.
2. A 6-character code appears on the dashboard's Telegram panel (`T`).
   It expires after 2 minutes.
3. The operator gives the code to the requester, who sends it to the bot.
4. The chat is authorized and starts receiving alerts. It can then send `/status`.

Three wrong codes lock that request out for 5 minutes. Approved chats are
stored in `data/telegram_auth.json`, which both `./siskamlan run` and
`./siskamlan tui` read. In the `T` panel, `x` rejects a pending request or
revokes an approved chat.

Upgrading from `TELEGRAM_CHAT_ID`: that variable is no longer read. Existing
chats receive no alerts until each one completes the code step once.

Bot commands:

| Command | For | Shows |
|---|---|---|
| `/start` | anyone | requests access |
| `/status` | approved chats | pipeline state, database reachability, last ingest, anomaly counts |

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

The dashboard list shows a `MATCHES` column, and the edit form shows the
condition in words. The form can only *rewrite* a single `event` filter
(`contains_any`, or `contains` with one value). A nested `when` tree and
`suppress_by` are shown read-only and saved back untouched, so editing a rate
can never widen a rule into one that matches every row. To change a nested
condition, edit the YAML by hand.

### `config/parsers.yaml`

New log types are supported without rebuilding. A device profile matches by
hostname and maps keywords onto structured columns.

An empty `devices: []` list is normal: the built-in parser then handles every
line. The `P` screen shows the newest raw lines from `logs.raw_line` under the
profile list, so you can see what is arriving before writing a profile.

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
| `q` | quit (from the dashboard; `ctrl+c` quits from any screen) |
| `p` | pause / resume live refresh |
| `/` | filter host, event, IP, MAC, SSID, interface, timestamp |
| `↑` `↓` / `j` `k` | scroll the focused pane |
| `tab` | switch focus between logs and anomalies |
| `enter` | open the selected row's detail (populated columns + raw line) |
| `o` | security overview (top sources, detections by type) |
| `e` | export the visible rows to CSV |
| `R` | rules editor |
| `P` | parser editor |
| `T` | Telegram access (approve or revoke chats) |
| `?` | help |

CSV export writes two files into `exports/` (`logs-<timestamp>.csv` and
`logs-<timestamp>-anomalies.csv`) and never overwrites an existing file; a
numeric suffix is added instead. Anomaly rows carry `type` and `entity`
extracted from the stored `features` document, so they join cleanly against
the log rows.

The dashboard uses the original black/blue palette (severity colours stay
red/orange/yellow/green) and adapts to the terminal: side-by-side panes on a
wide window, stacked panes when narrow, and reduced chrome — no stats row,
single-line filter — when the window is short. Columns are fitted to the
available width, so nothing wraps or overflows.

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
- Shutdown flushes the pending ingest buffer under a 5 second deadline. If the
  database is unreachable at that moment the buffered rows are dropped and the
  loss is logged, rather than blocking the exit.
- UDP syslog and bounded ingest batches can lose data under load; offsets are
  persisted atomically, but records already buffered at an unclean kill may repeat.
- Timestamp inference for traditional syslog assumes current year and UTC.
- IPv6 addresses in `src_ip`/`dst_ip`/`ospf_nbr`/`gateway` are parsed and
  stored; a malformed address is written as NULL rather than failing its batch.
  The address family is not used for network-prefix grouping or policy.
  Full RFC 5424 structured-data parsing is not supported.
- A failed anomaly write is logged and counted but does not abort the rest of
  that detection round, so one bad row cannot hide other detections.
- Telegram delivery is queued with bounded retries and may drop alerts when full.
- Database schema is initialized only for a fresh volume; future schema changes
  require explicit migrations rather than recreating the volume.

## Layout

`cmd/siskamlan/`: entrypoint · `internal/parser/`: syslog parsing + config ·
`internal/rules/`: detection engine · `internal/pipeline/`: tailer, ingest,
detector, alerts · `internal/store/`: PostgreSQL · `internal/tui/`: dashboard ·
`config/`: editable rules and parser definitions · `docker/`: images/schema ·
`data/syslog/`: collected logs · `exports/`: CSV output.
