# Modal detail screens for log rows and anomaly rows.

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

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
        max-height: 20;
        border: solid $accent;
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
            yield Static(f"[bold]Device:[/] {self.row.get('device', '')}")
            yield Static(f"[bold]Src IP:[/]  {self.row.get('src_ip', '')}")
            yield Static(f"[bold]Dst IP:[/]  {self.row.get('dst_ip', '')}")
            yield Static(f"[bold]Proto:[/]  {self.row.get('proto', '')}")
            yield Static(f"[bold]Port:[/]   {self.row.get('port', '')}")


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
        sev = self.row.get("severity", "")
        score = self.row.get("score", "")
        desc = self.row.get("description", "")
        with Vertical(id="anomaly-card"):
            yield Static(f"[bold]Severity:[/] {sev}")
            yield Static(f"[bold]Score:[/]   {score}")
            yield Static(f"[bold]Description:[/] {desc}")
