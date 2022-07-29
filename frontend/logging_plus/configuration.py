import os
from appdirs import user_log_dir

# environment variables (always prefixed by "TOOLNAME_")
LOG_SUB_DIRECTORY = 'LOG_SUB_DIRECTORY'
LOG_DIRECTORY = 'LOG_DIRECTORY'
LOG_LEVEL = 'LOG_LEVEL'
LOGGING_ENABLED = 'LOGGING_ENABLED'


def get_log_root_directory(tool_name: str):
    environment_variable = tool_name.upper() + '_' + LOG_DIRECTORY
    default_logging_dir = user_log_dir(tool_name)
    logging_dir = os.getenv(environment_variable, default_logging_dir)
    return logging_dir

def get_log_sub_directory(tool_name: str):
    environment_variable = tool_name.upper() + '_' + LOG_SUB_DIRECTORY
    log_sub_directory = os.getenv(environment_variable, 'default')
    return log_sub_directory


def get_log_level_label(tool_name: str):
    environment_variable = tool_name.upper() + '_' + LOG_LEVEL
    log_level_label = os.getenv(environment_variable, 'INFO')
    return log_level_label


def get_logging_enabled(tool_name: str):
    environment_variable = tool_name.upper() + '_' + LOGGING_ENABLED
    logging_enabled = get_environment_variable_bool(environment_variable, False)
    return logging_enabled


###########
# HELPERS #
###########


def string_to_bool(s: str, default: bool):
    if s in ['true', '1', 't', 'y', 'yes']:
        return True
    elif s in ['false', '0', 'f', 'n', 'no']:
        return False
    elif s is None:
        return default
    else:
        raise ValueError(f'Cannot interpret "{s}" as a boolean')


def get_environment_variable_bool(key: str, default: bool):
    ret = os.environ.get(key)
    ret = string_to_bool(ret, default=default)
    return ret
