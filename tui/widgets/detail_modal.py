# Modal detail screens for log rows and anomaly rows.

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from tui.theme import ACCENT, MUTED

BORDER_TITLE = "Detail"


# Card showing a single log entry's details.
class LogDetailScreen(ModalScreen):

    CSS = """
    LogDetailScreen {
        align: center middle;
    }
    #log-card {
        width: 60;
        height: auto;
        max-height: 30;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #log-card Static {
        height: auto;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def __init__(self, row: dict):
        super().__init__()
        self.row = row

    def compose(self) -> ComposeResult:
        with Vertical(id="log-card"):
            yield Static(f"[bold]Time:[/]   {self.row.get('time', '')}")
            yield Static(f"[bold]Device:[/] {self.row.get('device', '')}")
            yield Static(f"[bold]Event:[/]  {self.row.get('event', '')}")
            # Entity duplicates Src/Dst IP on firewall rows (COALESCE falls
            # through to dst_ip) — show it only when it adds information.
            entity = self.row.get("entity", "") or ""
            if entity and entity not in (self.row.get("src_ip", ""), self.row.get("dst_ip", "")):
                yield Static(f"[bold]Entity:[/] {entity}")
            for label, key in (
                ("Src IP", "src_ip"), ("Dst IP", "dst_ip"),
                ("Proto", "proto"), ("Port", "port"),
                ("Action", "action"),
                ("MAC", "mac"), ("VLAN", "vlan_id"),
                ("Iface", "ifname"), ("Peer", "peer_ifname"),
                ("STP root", "stp_root"), ("SSID", "ssid"),
                ("Radio", "radio"), ("Reason", "reason"),
                ("Signal", "signal_dbm"), ("Tx rate", "tx_rate_mbps"),
                ("EAP", "eap_status"), ("OSPF nbr", "ospf_nbr"),
                ("Gateway", "gateway"), ("Route", "route_dst"),
                ("DHCP MAC", "dhcp_mac"), ("Conntrack", "conntrack_count"),
                ("Src port", "src_port"), ("Client MAC", "client_mac"),
            ):
                val = self.row.get(key, "")
                if val not in ("", None):
                    yield Static(f"[bold]{label}:[/] {val}")


# Card showing a single anomaly entry's details.
class AnomalyDetailScreen(ModalScreen):

    CSS = """
    AnomalyDetailScreen {
        align: center middle;
    }
    #anomaly-card {
        width: 60;
        height: auto;
        max-height: 20;
        border: solid $warning;
        background: $surface;
        padding: 1 2;
    }
    #anomaly-card Static {
        height: auto;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def __init__(self, row: dict):
        super().__init__()
        self.row = row

    def compose(self) -> ComposeResult:
        with Vertical(id="anomaly-card"):
            yield Static(f"ID: {self.row.get('id', '')} · Repeats: {self.row.get('repeat_count', 1)}")
            yield Static(f"[bold]Severity:[/] {self.row.get("severity", "")}")
            yield Static(f"[bold]Score:[/]   {self.row.get("score", "")}")
            yield Static(f"[bold]Description:[/] {self.row.get("description", "")}")


# Security overview modal — severity breakdown, top sources, detection types.
class SecurityOverviewScreen(ModalScreen):

    CSS = """
    SecurityOverviewScreen {
        align: center middle;
    }
    #overview-card {
        width: 50;
        height: auto;
        max-height: 30;
        border: solid $warning;
        background: $surface;
        padding: 1 2;
    }
    #overview-card Static {
        height: auto;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        from db.init import get_connection
        from tui.queries import (
            SQL_STATS_ANOMALIES, SQL_SECURITY_SOURCES, SQL_SECURITY_DETECTIONS,
        )

        sev_crit = sev_high = sev_med = sev_low = 0
        sources = []
        detections = []

        conn = None
        error = None
        try:
            conn = get_connection()
            cur = conn.cursor()

            cur.execute(SQL_STATS_ANOMALIES)
            r = cur.fetchone()
            if r:
                _, _, sev_crit, sev_high, sev_med, sev_low = r

            cur.execute(SQL_SECURITY_SOURCES)
            sources = cur.fetchall()

            cur.execute(SQL_SECURITY_DETECTIONS)
            detections = cur.fetchall()

            cur.close()
            conn.close()
        except Exception:
            error = "Database unavailable — overview could not be loaded."
        finally:
            if conn is not None:
                conn.close()

        max_src = sources[0][1] if sources else 1

        with Vertical(id="overview-card"):
            yield Static("[bold white]SECURITY OVERVIEW[/]")
            if error:
                yield Static(error, markup=False)
            yield Static("─" * 44)
            yield Static("")
            yield Static(f"  CRITICAL     [bold red]{sev_crit}[/]")
            yield Static(f"  HIGH         [bold orange]{sev_high}[/]")
            yield Static(f"  MEDIUM       [bold yellow]{sev_med}[/]")
            yield Static(f"  LOW          {sev_low}")
            yield Static("")
            yield Static("[bold]TOP SOURCES[/]")
            for ip, cnt in sources:
                bar = self._bar(cnt / max_src)
                yield Static(f"  {ip:<16} {bar}  {cnt}")
            if not sources:
                yield Static("  (none)")
            yield Static("")
            yield Static("[bold]DETECTION TYPES[/]")
            for dtype, cnt in detections:
                yield Static(f"  {dtype:<16} {cnt}")
            if not detections:
                yield Static("  (none)")

    def _bar(self, pct):
        filled = int(pct * 15)
        return (
            f"[{ACCENT}]{'█' * filled}[/]"
            f"[{MUTED}]{'░' * (15 - filled)}[/]"
        )
