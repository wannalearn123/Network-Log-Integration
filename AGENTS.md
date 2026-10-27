# SISKAMLAN contributor instructions

See README.md for setup, architecture, configuration and runtime limitations.

- Go 1.24+; build with `make build`, run with `./siskamlan`.
- Python 3.12+ is only needed for the archived `train/` decision record.
- Compose configuration is at repository root: `docker compose up -d`.
- `.env` is loaded at startup. Never commit credentials/runtime data.
- Runtime detection is rules-only. ML experiments under `train/` are archived.
- Go verification: `make test` and `make vet`.
- Compose verification: `docker compose config --quiet`.
- Preserve existing named database volumes and user data during changes.
- Retention defaults to 7 days for logs / 30 for anomalies; 0 disables it.
- Detector windows are 30 seconds with a 15-second cadence.
- Rules live in `config/rules.yaml`; parser profiles in `config/parsers.yaml`.
  Both hot-reload and are editable from the dashboard (`R` and `P`).
- An invalid config edit is rejected and the last good config keeps running.
- Use structured anomaly `features.type` / `features.entity` for analytics,
  not regex parsing of human descriptions.
- Behaviour is pinned by two fixtures: `internal/parser/testdata/golden.jsonl`
  (parity with the former C parser) and `internal/rules/testdata/python_hits.txt`
  (parity with the former Python detector). Update them only with a deliberate
  behaviour change. IPv6 lines are the one sanctioned divergence: the C parser
  truncated them, so the parity test asserts valid IPv6 instead of byte equality.
- IPv4 and IPv6 addresses are accepted. The store writes an unparseable
  address as NULL instead of failing the batch, so a bad value can never
  poison ingest.