import logging
import logging.handlers as logging_handlers
import os
from typing import Dict

from logging_plus.formatters import full_formatter


class FilterPerName(logging.Filter):
    """
    Filter which only preserves log records whose level lies above a given threshold (defined per name)
    """
    # https://docs.python.org/3/library/logging.html#filter-objects

    def __init__(self, level_per_name: Dict[str, int]):
        self.level_per_name = level_per_name
        super().__init__()

    def filter(self, log_record: logging.LogRecord):
        for name, level in self.level_per_name.items():
            if log_record.name.startswith(name) and log_record.levelno >= level:
                return True
        return False


def log_to_handler_by_level(handler: logging.Handler, level_per_name: Dict[str, int]):
    """
    Pass log records to handler which satisfy "level_per_name"
    """
    # filter
    f = FilterPerName(level_per_name)
    handler.addFilter(f)

    logger = logging.getLogger('')
    logger.addHandler(handler)


def get_rotating_file_handler(
        log_directory: str,
        file_name: str,
        log_level=None,
        formatter=full_formatter,
        mode='a',
        maxBytes=10_000_000,
        backupCount=30,
        encoding=None,
        delay=True
):
    """

    Args:
        log_directory: the directory to place all logs into
        file_name: the basename of the files
        log_level: ignore records below this level
        formatter: default formatter
        mode:
        maxBytes: rollover after bytes (default: 10MB)
        backupCount: only keep the backupCount most recent files
        encoding: open file with this encoding
        delay: file opening is deferred until the first call to emit()

    Returns:

    """
    # ensure directory exists
    os.makedirs(log_directory, exist_ok=True)
    f = os.path.join(log_directory, file_name)

    # create handler
    file_handler = logging_handlers.RotatingFileHandler(
        f,
        mode=mode,
        maxBytes=maxBytes,
        backupCount=backupCount,
        encoding=encoding,
        delay=delay
    )

    # do initial rollover (WHY?)
    file_handler.doRollover()

    # set log_level
    if log_level is not None:
        file_handler.setLevel(log_level)

    # set formatter
    if formatter is not None:
        file_handler.setFormatter(formatter)

    return file_handler
