#!/usr/bin/env python3
# Network LAN Monitor — TUI Dashboard
#
# Real-time terminal dashboard for the network monitoring system.
# Displays live logs, anomaly alerts, and system stats.
#
# Usage:
# .venv/bin/python tui/app.py
# .venv/bin/python run.py          # starts orchestrator + TUI

import sys
from pathlib import Path

# Add project root to path
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
from tui.widgets.stats_bar import StatsBar
from tui.widgets.search_bar import SearchBar


    # Network LAN Monitor TUI Dashboard.
class NetworkMonitor(App):

    CSS = """
    Screen {
        layout: vertical;
    }

    #status-bar {
        height: 1;
        padding: 0 1;
        background: $accent;
        color: $text;
        text-style: bold;
    }

    #search-bar {
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }

    #search-bar {
        width: 100%;
    }

    #data-area {
        height: 1fr;
    }

    #data-area > #log-stream {
        width: 3fr;
        height: 100%;
        border: solid $accent;
    }

    #data-area > #anomaly-panel {
        width: 2fr;
        height: 100%;
        border: solid $warning;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("escape", "dismiss", "Close"),
        Binding("slash", "focus_search", "Search", show=True),
    ]

    paused: reactive[bool] = reactive(False)
    poll_interval = 2.0  # seconds
    _last_stats: dict = {}
    _last_search: str = ""

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
        # Default focus: device log stream, not the anomaly panel.
        # Deferred past autofocus so it wins the mount-time focus race.
        self.call_after_refresh(self._focus_log_stream)

    def _focus_log_stream(self):
        self.set_focus(self._log_table)

    def action_focus_search(self):
        self._search_bar.focus()

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
            like = f"%{search}%" if search else None

            if like:
                cur.execute(SQL_LOGS_SEARCH, (like, like, like, like, like, like))
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


if __name__ == "__main__":
    app = NetworkMonitor()
    app.title = "Network LAN Monitor"
    app.run()
