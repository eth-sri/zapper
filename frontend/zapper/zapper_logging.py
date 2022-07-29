import logging

from logging_plus.default_logging import enable_default_logging_on_flag

# enable default logging
enable_default_logging_on_flag('zapper')

# allow importing necessary logging functionality from this package (this implicitly enabling default logging)
# See also https://docs.python.org/3/howto/logging-cookbook.html for proper logging
getLogger = logging.getLogger
