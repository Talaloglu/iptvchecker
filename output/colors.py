"""
ANSI color helpers for cross-platform colored terminal output.
Works on Windows 10+ and all Unix terminals. Zero dependencies.
"""
import os
import sys


def _enable_windows_ansi():
    """Enable ANSI escape code processing on Windows 10+."""
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # STD_OUTPUT_HANDLE = -11
            handle = kernel32.GetStdHandle(-11)
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


# Enable on import
_enable_windows_ansi()

# Detect if colors are supported
COLORS_ENABLED = (
    hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
) or os.environ.get('FORCE_COLOR', '')


class Color:
    """ANSI color codes."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Regular colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

    # Backgrounds
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


def colorize(text, color):
    """Wrap text with ANSI color codes if colors are enabled."""
    if not COLORS_ENABLED:
        return text
    return f"{color}{text}{Color.RESET}"


def red(text):
    return colorize(text, Color.RED)


def green(text):
    return colorize(text, Color.GREEN)


def yellow(text):
    return colorize(text, Color.YELLOW)


def blue(text):
    return colorize(text, Color.BLUE)


def cyan(text):
    return colorize(text, Color.CYAN)


def magenta(text):
    return colorize(text, Color.MAGENTA)


def gray(text):
    return colorize(text, Color.GRAY)


def bold(text):
    return colorize(text, Color.BOLD)


def success(text):
    """Green bold text for success messages."""
    return colorize(text, Color.BOLD + Color.GREEN)


def error(text):
    """Red bold text for error messages."""
    return colorize(text, Color.BOLD + Color.RED)


def warning(text):
    """Yellow text for warning messages."""
    return colorize(text, Color.YELLOW)


def info(text):
    """Cyan text for info messages."""
    return colorize(text, Color.CYAN)


def header(text):
    """Magenta bold text for headers."""
    return colorize(text, Color.BOLD + Color.MAGENTA)
