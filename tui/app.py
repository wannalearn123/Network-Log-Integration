#!/usr/bin/env python3
# Real-time terminal dashboard for SISKAMLAN (Sistem Keamanan LAN).
import sys
from pathlib import Path

# Add project root to path (must be before project imports)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.containers import Horizontal
from textual.widgets import Footer
from db.init import get_connection
from tui.queries import (
    SQL_LOGS, SQL_LOGS_SEARCH,
    SQL_ANOMALIES, SQL_ANOMALIES_SEARCH,
    SQL_STATS_LOGS, SQL_STATS_ANOMALIES,
)
from tui.widgets.log_stream import LogStream
from tui.widgets.anomaly_panel import AnomalyPanel
from tui.widgets.detail_modal import LogDetailScreen, AnomalyDetailScreen, SecurityOverviewScreen
from tui.csv_export import export_view, plan_export
from tui.widgets.export_modal import ExportConfirmScreen
from tui.widgets.about_screen import AboutScreen
from tui.widgets.stats_bar import StatsBar
from tui.widgets.search_bar import SearchBar
from tui.theme import MONITORING_BLUE, BACKGROUND


# SISKAMLAN TUI Dashboard.


class NetworkMonitor(App):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register_theme(MONITORING_BLUE)
        self.theme = "monitoring-blue"

    CSS = f"""
    Screen {{
        layout: vertical;
    }}

    #status-bar {{
        height: 1;
        padding: 0 1;
        background: $accent;
        color: {BACKGROUND};
        text-style: bold;
    }}

    #search-bar {{
        height: auto;
        width: 100%;
        padding: 0 1;
        margin: 1 0;
    }}

    #data-area {{
        height: 1fr;
    }}

    #data-area > #log-stream {{
        width: 3fr;
        height: 100%;
        border: solid $accent;
    }}

    #data-area > #anomaly-panel {{
        width: 2fr;
        height: 100%;
        border: solid $primary;
    }}
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("escape", "dismiss", "Close", show=False),
        Binding("tab", "focus_next", "Next", show=False, priority=True),
        Binding("slash", "focus_search", "Search", show=True),
        Binding("space", "security_overview",
                "Overview", show=True, priority=True),
        Binding("i", "about", "About", show=True),
        Binding("e", "export_csv", "Export", show=True),
    ]

    paused: reactive[bool] = reactive(False)
    poll_interval = 1.0
    _last_stats: dict = {}
    _last_search: str = ""
    _pause_before_modal: bool = False

    def compose(self) -> ComposeResult:
        yield StatsBar(id="status-bar")
        yield SearchBar(id="search-bar")
        with Horizontal(id="data-area"):
            yield LogStream(id="log-stream")
            yield AnomalyPanel(id="anomaly-panel")
        yield Footer()

    def on_mount(self):
        self._log_table = self.query_one("#log-stream", LogStream)
        self._anom_table = self.query_one("#anomaly-panel", AnomalyPanel)
        self._status_bar = self.query_one("#status-bar", StatsBar)
        self._search_bar = self.query_one("#search-bar", SearchBar)
        self.set_interval(self.poll_interval, self.refresh_data)
        self.refresh_data()
        # Defer focus to log stream past autofocus.
        self.call_after_refresh(self._focus_log_stream)

    def _focus_log_stream(self):
        self.set_focus(self._log_table)

    def action_focus_search(self):
        self._search_bar.focus()

        # Open a detail modal over the selected table row and pause the feed.
    def _open_detail(self, screen):
        self._pause_before_modal = self.paused
        self.paused = True
        self._status_bar.update_stats(self._last_stats, paused=True)
        self.push_screen(screen, callback=self._close_detail)

        # Resume the feed when the detail modal is dismissed.
    def _close_detail(self, _result=None):
        self.paused = self._pause_before_modal
        self._status_bar.update_stats(self._last_stats, paused=self.paused)
        self.refresh_data()

        # Enter/click on a log or anomaly row opens its detail card.
    def on_data_table_row_selected(self, event):
        idx = event.cursor_row
        if event.control.id == "log-stream":
            rows = self._log_table._rows
            if 0 <= idx < len(rows):
                self._open_detail(LogDetailScreen(rows[idx]))
        elif event.control.id == "anomaly-panel":
            rows = self._anom_table._rows
            if 0 <= idx < len(rows):
                self._open_detail(AnomalyDetailScreen(rows[idx]))

        # Poll database and update all widgets.
    def refresh_data(self):
        if self.paused:
            return

        conn = cur = None
        try:
            conn = get_connection()
            cur = conn.cursor()

            search = self._search_bar.search_text.strip()
            self._last_search = search
            # Escape LIKE wildcards so user input is treated literally.
            # With ESCAPE '\\' in SQL: \% = literal %, \_ = literal _
            if search:
                like = "%" + search.replace("\\", "\\\\") \
                                   .replace("%", "\\%") \
                                   .replace("_", "\\_") + "%"
            else:
                like = None

            if like:
                cur.execute(SQL_LOGS_SEARCH,
                            (like,) * 10)
            else:
                cur.execute(SQL_LOGS)
            self._log_table.populate(cur.fetchall())

            if like:
                cur.execute(SQL_ANOMALIES_SEARCH, (like, like))
            else:
                cur.execute(SQL_ANOMALIES)
            self._anom_table.populate(cur.fetchall())

            cur.execute(SQL_STATS_LOGS)
            r = cur.fetchone()
            total, hour, devices = r or (0,) * 3

            cur.execute(SQL_STATS_ANOMALIES)
            r = cur.fetchone()
            anom, anom_h, c, h, m, lo = r or (0,) * 6
            stats = {
                "total_logs": total, "logs_1h": hour, "active_devices": devices,
                "total_anomalies": anom, "anomalies_1h": anom_h,
                "sev_crit": c, "sev_high": h, "sev_med": m, "sev_low": lo,
            }
            self._status_bar.update_stats(stats, paused=self.paused)
            self._last_stats = stats

        except Exception as e:
            self.title = f"Error: {e}"
        finally:
            try:
                if cur is not None:
                    cur.close()
            except Exception:
                pass
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

    def action_toggle_pause(self):
        self.paused = not self.paused
        self._status_bar.update_stats(self._last_stats, paused=self.paused)

    def action_dismiss(self):
        if self._search_bar.has_focus:
            self._search_bar.clear_search()
            self._search_bar.blur()

    def action_security_overview(self):
        self._open_detail(SecurityOverviewScreen())

    def action_about(self):
        # Don't hijack typing in the search bar.
        if self._search_bar.has_focus:
            return
        self._open_detail(AboutScreen())

    def action_export_csv(self):
        # Don't hijack typing in the search bar.
        if self._search_bar.has_focus:
            return
        # One stamp for both the modal preview and the actual write, so the
        # filenames shown are exactly the filenames created.
        log_path, anom_path = plan_export()
        self._export_stamp = log_path.stem.removeprefix("logs-")
        self.push_screen(
            ExportConfirmScreen(
                log_path, anom_path,
                len(self._log_table._rows), len(self._anom_table._rows),
            ),
            callback=self._do_export,
        )

        # Write the CSVs only after the user confirms; nothing touches disk
        # when the modal is cancelled.
    def _do_export(self, confirmed):
        if not confirmed:
            self.title = "SISKAMLAN — export cancelled"
            return
        result = export_view(
            self._log_table._rows, self._anom_table._rows,
            stamp=self._export_stamp,
        )
        if result:
            log_path, _anom_path, n = result
            self.title = f"SISKAMLAN — exported {n} rows to {log_path.parent}/"
        else:
            self.title = "SISKAMLAN — CSV export failed"


if __name__ == "__main__":
    app = NetworkMonitor()
    app.title = "SISKAMLAN"
    app.run()
