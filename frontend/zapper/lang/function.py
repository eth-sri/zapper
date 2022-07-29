import inspect
from collections import OrderedDict
from dataclasses import dataclass
from typing import Type, TYPE_CHECKING, Dict, get_type_hints, Optional, Callable

from zapper.utils.inspection import get_and_resolve_type_hints

if TYPE_CHECKING:
    from zapper.lang.contract import Contract
    from zapper.lang.types import ZapperType


@dataclass
class Function:
    contract_type: Type['Contract']
    name: str
    argument_types: Dict[str, 'ZapperType']
    return_type: Optional['ZapperType']
    is_private: bool
    is_private_for: Optional[str]
    is_constructor: bool

    def __post_init__(self):
        from zapper.lang.types import is_zapper_type
        from zapper.lang.contract import Contract
        assert issubclass(self.contract_type, Contract)
        assert isinstance(self.name, str)
        assert isinstance(self.argument_types, dict)
        for t in self.argument_types.values():
            assert is_zapper_type(t), f'Unexpected type {t}'
        assert is_zapper_type(self.return_type)
        assert isinstance(self.is_private, bool)
        assert isinstance(self.is_constructor, bool)


def extract_function(cls: Type, function_name: str):
    if not hasattr(cls, function_name):
        raise ValueError(f"Class {cls} does not have attribute {function_name}.")
    f = getattr(cls, function_name)

    if not callable(f):
        raise ValueError(f"Class {cls} has a non-function attribute {function_name} containing {f}.")

    types, return_type = extract_types(cls, f)

    is_private = hasattr(f, 'is_private')
    is_private_for = None
    if is_private and hasattr(f, 'is_private_for'):
        is_private_for = f.is_private_for

    is_constructor = hasattr(f, 'is_constructor')
    if is_constructor:
        from zapper.lang.types import Uint
        assert return_type == Uint

        return_type = cls

    return Function(cls, function_name, types, return_type, is_private, is_private_for, is_constructor)


def extract_types(cls: Type, f: Callable):
    types = get_and_resolve_type_hints(cls, f)

    if 'return' in types:
        return_type = types['return']
        del types['return']
    else:
        # default return value is 0
        from zapper.lang.types import Uint
        return_type = Uint

    arg_names = inspect.getfullargspec(f).args

    # add self
    assert arg_names[0] == 'self', f"First argument of {f.__name__} should be called 'self'"
    types['self'] = cls

    # ensure reserved "sender_is_self" argument is not declared
    assert "sender_is_self" not in arg_names, f"Function {f.__name__} declares reserved argument 'sender_is_self'"

    # ensure correct sorting
    types = OrderedDict([(arg, types[arg]) for arg in arg_names])

    return types, return_type
