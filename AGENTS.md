# SISKAMLAN contributor instructions

See README.md for setup, architecture, configuration and runtime limitations.

- Python 3.12+; use `.venv/bin/python` or an existing `venv/bin/python`.
- Build collector with `make -C collector` before running the pipeline.
- Compose configuration is at repository root: `docker compose up -d`.
- `.env` is loaded by `db/init.py`. Never commit credentials/runtime data.
- Runtime detection is rules-only. ML experiments under `train/` are archived.
- C verification: `make -C collector test`.
- Python verification: `python -m unittest discover -s tests -v`.
- Compose verification: `docker compose config --quiet`.
- Preserve existing named database volumes and user data during changes.
- Retention defaults to 7 days for logs / 30 for anomalies; 0 disables it.
- Detector windows are 30 seconds with a 15-second cadence.
- Use structured anomaly `features.type` / `features.entity` for analytics,
  not regex parsing of human descriptions.
