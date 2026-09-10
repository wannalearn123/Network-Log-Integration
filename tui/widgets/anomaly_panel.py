# Anomaly alerts DataTable panel.

from textual.widgets import DataTable

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


    # Anomaly alerts panel showing recent detections.
class AnomalyPanel(DataTable):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rows: list[dict] = []

    def on_mount(self):
        self.add_columns("Time", "Severity", "Score", "Description")
        self.cursor_type = "row"

        # Replace all rows with new data from query results.
    def populate(self, rows: list):
        self.clear()
        self._rows.clear()
        for i, row in enumerate(rows):
            ts = row[1].strftime("%H:%M:%S") if row[1] else ""
            sev = row[2] or ""
            score = f"{row[3]:.2f}" if row[3] is not None else "0.00"
            desc = row[4] or ""
            icon = SEVERITY_ICONS.get(sev, "⚪")
            self.add_row(ts, f"{icon} {sev}", score, desc, key=f"anom-{i}")
            self._rows.append({
                "time": row[1].strftime("%Y-%m-%d %H:%M:%S") if row[1] else "",
                "severity": sev,
                "score": score,
                "description": desc,
            })
