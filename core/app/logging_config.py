"""Minimal standard-library logging configuration for SecureTrap.

Configures a single named logger ("securetrap") with a rotating file
handler and a console handler, both using the same timestamped
format. This module is configuration only: it sets up handlers — it
does not decide what gets logged. That's up to whoever calls
`logging.getLogger("securetrap")` (or the returned logger) and logs
through it.

Standard-library `logging` only — no third-party logging package.

Callers of this logger must never log secrets, passwords, tokens, or
raw authentication credentials. Nothing in this module introduces such
logging itself; this is guidance for callers.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Union

LOGGER_NAME = "securetrap"

_LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per log file before rotating
_BACKUP_COUNT = 3


def configure_logging(log_file: Union[str, Path], level: int = logging.INFO) -> logging.Logger:
    """Configure and return the SecureTrap logger.

    Creates the log file's parent directory if it doesn't exist, then
    attaches exactly one RotatingFileHandler and one console
    StreamHandler to the "securetrap" logger, both using the same
    timestamped format.

    Idempotent: calling this more than once (e.g. across repeated
    calls in the same process, or across tests) does not duplicate
    handlers — any handlers already attached to the SecureTrap logger
    are removed and closed first.

    Args:
        log_file: Path to the rotating log file. Parent directories
            are created if they do not exist.
        level: Logging level applied to the logger and both handlers.
            Defaults to logging.INFO.

    Returns:
        The configured "securetrap" Logger.
    """
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    # Kept self-contained: SecureTrap's logger doesn't rely on (or
    # bleed into) whatever the root logger happens to be configured
    # with elsewhere in the process.
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_logger() -> logging.Logger:
    """Return the SecureTrap logger, without (re)configuring it."""
    return logging.getLogger(LOGGER_NAME)