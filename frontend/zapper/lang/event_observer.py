from abc import abstractmethod, ABC
from typing import Any, Type, TYPE_CHECKING, Callable

from zapper.lang.field import Field
from zapper.lang.function import Function, extract_function

if TYPE_CHECKING:
    from zapper.lang.contract import Contract


class EventObserver(ABC):
    """
    Observer on key events when stepping through a contract function. Useful for:
    - building IR during compilation
    - testing
    """

    def __init__(self, contract_type: Type['Contract'] = None):
        self.contract_type = contract_type

    @abstractmethod
    def require(self, e):
        pass

    @abstractmethod
    def require_equals(self, e1, e2):
        pass

    @abstractmethod
    def if_then_else(self, condition, e_true, e_false):
        pass

    @property
    @abstractmethod
    def me(self):
        pass

    @property
    @abstractmethod
    def owner(self):
        pass

    @property
    @abstractmethod
    def address(self):
        pass

    @owner.setter
    @abstractmethod
    def owner(self, value):
        pass

    @abstractmethod
    def create_new_object(self, constructor_function: Callable, *args):
        pass

    @abstractmethod
    def kill(self):
        pass

    @abstractmethod
    def fresh(self):
        pass

    @abstractmethod
    def now(self):
        pass

    ##########
    # OTHERS #
    ##########

    @abstractmethod
    def function_call(self, function: Function, *args, sender_is_self=False):
        pass

    ########
    # READ #
    ########

    def __getattr__(self, item):
        if item == 'contract_type' or self.contract_type is None:
            # prevent infinite loop
            return super().__getattribute__(item)
        if item in self.contract_type.zapper_fields:
            # zapper field reads are recorded
            fields = self.contract_type.zapper_fields
            return self.read_field(fields[item])
        elif item in self.contract_type.zapper_functions:
            # zapper functions are replaced by mock functions which record calls
            def mock_function(*args, sender_is_self=False):
                function = extract_function(self.contract_type, item)
                return self.function_call(function, self, *args, sender_is_self=sender_is_self)
            return mock_function
        else:
            # other reads are handled normally
            return super().__getattribute__(item)

    @abstractmethod
    def read_field(self, field: Field) -> Any:
        pass

    #########
    # WRITE #
    #########

    def __setattr__(self, key, value):
        if key == 'contract_type' or self.contract_type is None:
            # prevent reading field before it is set
            return super().__setattr__(key, value)
        if key in self.contract_type.zapper_fields:
            # zapper field writes are recorded
            field = self.contract_type.zapper_fields[key]
            return self.write_field(field, value)
        else:
            # other field writes are handled normally
            return super().__setattr__(key, value)

    @abstractmethod
    def write_field(self, field: Field, e):
        pass
