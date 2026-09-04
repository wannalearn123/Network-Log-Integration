# Bottom stats bar showing aggregate counts.

from textual.widgets import Static


    # Bottom bar with log counts, device count, and anomaly breakdown.
class StatsBar(Static):

    def __init__(self, **kwargs):
        super().__init__("Loading...", **kwargs)

        # Update the stats bar with new counts.
    def update_stats(self, stats: dict, paused: bool = False):
        status = "⏸  PAUSED" if paused else "▶ LIVE"
        parts = [
            status,
            f"Logs: {stats.get('total_logs', 0):,}",
            f"1h: {stats.get('logs_1h', 0):,}",
            f"Devices: {stats.get('active_devices', 0)}",
            f"Anomalies: {stats.get('total_anomalies', 0)}",
            (
                f"🔴{stats.get('sev_crit', 0)}"
                f" 🟠{stats.get('sev_high', 0)}"
                f" 🟡{stats.get('sev_med', 0)}"
                f" 🟢{stats.get('sev_low', 0)}"
            ),
        ]
        self.update(" │ ".join(parts))
