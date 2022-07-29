from collections import OrderedDict
from typing import TypeVar, Iterable, List, Dict

T = TypeVar('T')


def get_duplicates(it: Iterable[T]) -> List[T]:
    unique = set()
    duplicates = []

    for x in it:
        if x in unique:
            duplicates.append(x)
        else:
            unique.add(x)

    return duplicates


K = TypeVar('K')
V = TypeVar('V')


def order_dictionary_by_keys(d: Dict[K, V]):
    items = sorted(d.items())
    ret = OrderedDict(items)
    return ret


def to_hex_str(x: int) -> str:
    s = hex(x)[2:]
    if len(s) % 2 != 0:
        # pad with leading zero to ensure even length
        s = "0" + s
    return s
