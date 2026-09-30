# Color theme for the TUI: logo-derived black + blue palette.
#
# Neutral (black) base with a single blue brand hue. Severity colors
# (red/orange/yellow/green emoji + markup) are intentionally left as-is
# in the widgets so alert levels stay instantly recognizable.

from textual.theme import Theme

# Neutral scale (black)
BACKGROUND = "#0A0A0A"  # app background — soft black
SURFACE = "#101214"     # raised surfaces (modal cards, panels)
TEXT = "#E6E6E6"        # primary text
MUTED = "#8A8A8A"       # secondary text / inactive elements

# Blue scale (logo blue)
PRIMARY = "#1565A8"      # main brand blue
ACCENT = "#2B8FD6"       # bright blue — status bar, focus, active borders
ACCENT_LIGHT = "#5EB8F5"  # emphasis on black
ACCENT_DIM = "#1E6FA8"   # subdued blue

MONITORING_BLUE = Theme(
    name="monitoring-blue",
    primary=PRIMARY,
    secondary=PRIMARY,
    accent=ACCENT,
    warning=ACCENT,
    error=ACCENT_LIGHT,
    success=ACCENT_DIM,
    foreground=TEXT,
    background=BACKGROUND,
    surface=SURFACE,
    panel=SURFACE,
    boost=ACCENT,
    dark=True,
)
