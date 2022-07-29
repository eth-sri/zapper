from traceback import StackSummary, format_list
from typing import Type

from zapper.utils.inspection import get_qualified_name

from zapper.lang.types import Uint, Address, is_uint, is_address, is_zapper_type, is_reference, ZapperType, is_long

AssemblyType = Type[Uint] | Type[Address] | Type[Uint] | str


def is_assembly_type(t: AssemblyType):
    if is_uint(t):
        return True
    elif is_long(t):
        return True
    elif is_address(t):
        return True
    elif isinstance(t, str):
        return True
    else:
        return False


def zapper_type_to_assembly_type(t: ZapperType):
    assert is_zapper_type(t), f'Got {t}'
    if is_uint(t):
        return t
    elif is_long(t):
        return t
    elif is_address(t):
        return t
    else:
        assert is_reference(t)
        return get_qualified_name(t)


def check_assembly_type(t: AssemblyType, stack: StackSummary = None):
    if not is_assembly_type(t):
        raise AssemblyTypeError(f'Type {t} is not supported', stack)


def check_assembly_supertype(lhs_type: AssemblyType, rhs_type: AssemblyType, stack: StackSummary = None):
    """
    Ensure that lhs = rhs type-checks
    """
    check_assembly_type(lhs_type, stack=stack)
    check_assembly_type(rhs_type, stack=stack)
    if lhs_type != rhs_type:
        raise AssemblyTypeError(f"Mismatch between expected type ({lhs_type}) and actual type ({rhs_type})", stack)


def assembly_type_to_str(t: AssemblyType):
    if is_uint(t):
        return 'uint'
    elif is_long(t):
        return 'long'
    elif is_address(t):
        return 'address'
    elif isinstance(t, str):
        return t
    else:
        raise AssemblyTypeError(f'Not a valid assembly type: {t}')


class AssemblyTypeError(Exception):

    def __init__(self, msg, stack: StackSummary = None):
        self.msg = msg
        self.stack = stack

        full_message = msg

        if stack is not None:
            full_message += '\n\nStack trace of origin of error:\n\n' + ''.join(format_list(stack))

        super().__init__(full_message)
