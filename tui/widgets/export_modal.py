# Export confirmation modal — shows the exact CSV filenames and row
# counts before anything is written to disk.

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from tui.theme import ACCENT_LIGHT, MUTED


# Confirmation card for a CSV export; dismisses with True/False.
class ExportConfirmScreen(ModalScreen):

    CSS = """
    ExportConfirmScreen {
        align: center middle;
    }
    #export-card {
        width: 60;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #export-card Static {
        height: auto;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "confirm", "Export"),
    ]

    def __init__(self, log_path, anom_path, n_logs, n_anoms):
        super().__init__()
        self.log_path = Path(log_path)
        self.anom_path = Path(anom_path)
        self.n_logs = n_logs
        self.n_anoms = n_anoms

    def compose(self) -> ComposeResult:
        with Vertical(id="export-card"):
            yield Static(f"[bold {ACCENT_LIGHT}]EXPORT CSV[/]")
            yield Static("")
            yield Static(f"  {self.log_path.name}  [{MUTED}]{self.n_logs} rows[/]")
            yield Static(f"  {self.anom_path.name}  [{MUTED}]{self.n_anoms} rows[/]")
            yield Static("")
            yield Static(f"  [{MUTED}]to {self.log_path.parent}[/]")
            yield Static("")
            # Textual's markup parser drops unknown tags like [Enter], so the
            # key hints must be backslash-escaped to render literally.
            yield Static(r"  [bold]\[Enter][/] Export    "
                         rf"[{MUTED}]\[Esc] Cancel[/]")

    def action_confirm(self):
        self.dismiss(True)

    def action_cancel(self):
        self.dismiss(False)
