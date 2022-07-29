import logging

# Example:
# 2022-01-07_20-38-19 [WARNING, __main__]: Some text
full_formatter = logging.Formatter('%(asctime)s [%(levelname)7s, %(name)s]: %(message)s', datefmt="%Y-%m-%d_%H-%M-%S")

# Example:
# [WARNING, __main__] Some text
standard_formatter = logging.Formatter('[%(levelname)7s, %(name)s] %(message)s')

# Example:
# Some text
minimal_formatter = logging.Formatter('%(message)s')
