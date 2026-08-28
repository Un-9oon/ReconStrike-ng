import logging
import sys


logger = logging.getLogger("reconstrike-ng")


class _ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: "\033[37m",
        logging.INFO: "\033[36m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, datefmt: str = None, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if not self.use_color:
            return msg
        color = self.LEVEL_COLORS.get(record.levelno, self.RESET)
        return f"{color}{msg}{self.RESET}"


def setup_logging(
    verbose: bool = False,
    quiet: bool = False,
    no_color: bool = False,
    log_file: str = None,
) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    use_color = not no_color and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
    console.setFormatter(_ColorFormatter(fmt, datefmt, use_color=use_color))
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(fmt, datefmt))
        logger.addHandler(fh)
