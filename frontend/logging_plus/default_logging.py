import logging
import sys

from logging_plus.configuration import get_log_sub_directory, get_log_level_label, get_logging_enabled, \
    get_log_root_directory
from logging_plus.handlers import log_to_handler_by_level, get_rotating_file_handler
from logging_plus.formatters import standard_formatter
from logging_plus.log_directory import get_log_directory, now_string


def enable_default_logging_to_stdout(tool_name: str):
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(standard_formatter)
    level_per_name = {
        '': logging.WARNING,
        '__main__': logging.INFO,
        'logging_plus': logging.INFO,
        'tests': logging.INFO,
        tool_name: logging.INFO,
    }
    log_to_handler_by_level(stdout_handler, level_per_name)


def get_default_log_directory(tool_name: str):
    root_log_directory = get_log_root_directory(tool_name)
    log_sub_directory = get_log_sub_directory(tool_name)
    log_directory = get_log_directory(root_log_directory, log_sub_directory, True)
    return log_directory


def enable_default_logging_to_file(tool_name: str):
    log_directory = get_default_log_directory(tool_name)
    log_level_label = get_log_level_label(tool_name)
    file_name = log_level_label.lower() + '.log'
    handler = get_rotating_file_handler(log_directory, file_name, log_level_label)

    log_level = logging.getLevelName(log_level_label)
    level_per_name = {
        '': logging.INFO,
        '__main__': log_level,
        'logging_plus': logging.INFO,
        'tests': log_level,
        tool_name: log_level,
    }
    log_to_handler_by_level(handler, level_per_name)

    return handler


def enable_default_logging_on_flag(tool_name: str):
    logging_enabled = get_logging_enabled(tool_name)

    if logging_enabled:
        # override default behavior which blocks lower levels
        logger = logging.getLogger('')
        logger.setLevel(logging.NOTSET)

        enable_default_logging_to_stdout(tool_name)
        file_handler = enable_default_logging_to_file(tool_name)

        logger = logging.getLogger(__name__)
        logger.info('Enabled default logging to %s at %s', file_handler.baseFilename, now_string)
