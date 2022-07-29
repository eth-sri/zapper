import json
import os
import contextlib
import time

data_log_file = os.getenv('ZAPPER_DATA_LOG_FILE')
if data_log_file is not None:
    the_data_log_file = open(data_log_file, 'a')
    the_current_context = []


def write_data(data):
    if data_log_file is not None:
        data = {"context": the_current_context, "data": data}
        the_data_log_file.write(json.dumps(data))
        the_data_log_file.write("\n")
        the_data_log_file.flush()


@contextlib.contextmanager
def data_context(key):
    if data_log_file is not None:
        the_current_context.append(key)
        yield
        the_current_context.pop()
    else:
        yield


@contextlib.contextmanager
def time_measure(key):
    if data_log_file is not None:
        start = time.perf_counter()
        yield
        end = time.perf_counter()
        elapsed = end - start
        write_data({"time": {"key": key, "elapsed_sec": elapsed}})
    else:
        yield
