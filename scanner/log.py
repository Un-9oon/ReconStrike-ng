"""Centralized logging for ReconStrike."""

import logging
import sys


logger = logging.getLogger("reconstrike")


class _ColorFormatter(logging.Formatter):
    """Log formatter that adds colorama colors based on log level.

    Colors are applied only when output goes to a TTY and no_color is False.
    """

    LEVEL_COLORS = {
        logging.DEBUG: "\033[37m",      # white
        logging.INFO: "\033[36m",       # cyan
        logging.WARNING: "\033[33m",    # yellow
        logging.ERROR: "\033[31m",      # red
        logging.CRITICAL: "\033[1;31m", # bold red
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, datefmt: str = None, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self.use_color:
            color = self.LEVEL_COLORS.get(record.levelno, self.RESET)
            return f"{color}{msg}{self.RESET}"
        return msg


def setup_logging(
    verbose: bool = False,
    quiet: bool = False,
    no_color: bool = False,
    log_file: str = None,
) -> None:
    """Configure the ``reconstrike`` logger.

    Parameters
    ----------
    verbose : bool
        Set log level to DEBUG.
    quiet : bool
        Set log level to WARNING.
    no_color : bool
        Disable ANSI color codes in console output.
    log_file : str | None
        If provided, also write logs to this file (always without color).
    """
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logger.setLevel(level)

    # Remove any existing handlers (avoid duplicates on repeated calls)
    logger.handlers.clear()

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    use_color = not no_color and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
    console.setFormatter(_ColorFormatter(fmt, datefmt, use_color=use_color))
    logger.addHandler(console)

    # Optional file handler (never colored)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(fmt, datefmt))
        logger.addHandler(fh)
