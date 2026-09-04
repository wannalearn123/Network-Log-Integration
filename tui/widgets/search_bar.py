# Search bar widget for filtering logs and anomalies.

from textual.reactive import reactive
from textual.widgets import Input


    # Search input for filtering both log stream and anomaly panel.
class SearchBar(Input):

    _startup_focus_block: bool = True
    search_text: reactive[str] = reactive("")

    DEFAULT_CSS = """
    SearchBar {
        border: tall $border-blurred;
    }
    SearchBar:focus {
        border: tall orange;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(
            placeholder="Search logs & anomalies...",
            **kwargs,
        )

        # Block focus during startup only, allow it afterward.
        #
        # Blur is deferred via set_timer to avoid reentrant
        # focus/blur cycles inside the message handler.
    def on_focus(self):
        if self._startup_focus_block:
            self._startup_focus_block = False
            self.set_timer(0.05, self.blur)

        # Update reactive search text when user types.
    def on_input_changed(self, event: Input.Changed):
        self.search_text = event.value

        # Clear the search input.
    def clear_search(self):
        self.value = ""
        self.search_text = ""
