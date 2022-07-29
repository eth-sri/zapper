import os
from datetime import datetime


now = datetime.now()
now_string = now.strftime("%Y-%m-%d__%H-%M-%S__%f")


def get_log_directory(log_root_directory: str, log_sub_directory: str = None, use_time_sub_directory=False):
    directory = log_root_directory

    if log_sub_directory is not None:
        directory = os.path.join(directory, log_sub_directory)

    if use_time_sub_directory:
        process_id = str(os.getpid())
        log_directory_prefix = 'log__'
        time_sub_directory = log_directory_prefix + now_string + '__' + process_id
        directory = os.path.join(directory, time_sub_directory)

    return directory
