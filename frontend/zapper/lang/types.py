from typing import Type, Annotated

from zapper.lang.contract import Contract
from zapper.lang.type_address import Address

Uint = Annotated[int, 'Unsigned integer']   # numbers in [0, 2^120-1]  (representable in 15 bytes)
Long = Annotated[int, 'Large unsigned integer'] # large numbers in [0, p-1]

ZapperType = Type[Uint] | Type[Long] | Type[Address] | Type[Contract]


class AddressConst:
    def __init__(self, val: Address):
        self.val = val


class LongConst:
    def __init__(self, val: Long):
        self.val = val


def is_zapper_type(t: ZapperType):
    if t is None:
        return False

    if is_uint(t):
        return True
    elif is_long(t):
        return True
    elif is_address(t):
        return True
    elif is_reference(t):
        return True
    else:
        return False


def is_uint(t: ZapperType):
    return t == Uint


def is_address(t: ZapperType):
    return t == Address


def is_long(t: ZapperType):
    return t == Long


def is_reference(t: ZapperType):
    if t is None:
        return False
    elif is_uint(t):
        return False
    elif is_long(t):
        return False
    elif is_address(t):
        return False
    else:
        assert issubclass(t, Contract)
        return True


def is_uint_literal(x: int):
    return 0 <= x < 2**120


def check_zapper_type(t: ZapperType):
    if not is_zapper_type(t):
        raise ValueError(f'Type {t} is not supported')


def check_subtype(lhs_type: ZapperType, rhs_type: ZapperType):
    check_zapper_type(lhs_type)
    check_zapper_type(rhs_type)
    if lhs_type != rhs_type:
        raise ValueError(f"Mismatch between expected type ({lhs_type}) and actual type ({rhs_type})")
