# About / branding screen showing the program name and motto.

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from tui.theme import ACCENT_LIGHT, MUTED

APP_NAME = "SISKAMLAN"
APP_MOTTO = "WIDYUTA SANDHI WASKITA"


# Program identity card: name and motto.
class AboutScreen(ModalScreen):

    CSS = """
    AboutScreen {
        align: center middle;
    }
    #about-card {
        width: 32;
        height: auto;
        max-height: 30;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #about-card Static {
        height: auto;
        text-align: center;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="about-card"):
            yield Static(f"[bold {ACCENT_LIGHT}]{APP_NAME}[/]")
            yield Static(f"[{MUTED}]{APP_MOTTO}[/]")
