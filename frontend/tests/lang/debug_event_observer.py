from typing import Any, Type, TYPE_CHECKING, Callable

from zapper.lang.field import Field
from zapper.lang.event_observer import EventObserver
from zapper.lang.function import Function
from zapper.utils.inspection import get_class_that_defined_method

if TYPE_CHECKING:
    from zapper.lang.contract import Contract


class DebugEventObserver(EventObserver):

    def __init__(self, contract_type: Type['Contract']):
        super().__init__(contract_type)
        self.ops = []

    def require(self, e):
        self.ops.append("require")

    def require_equals(self, e1, e2):
        self.ops.append("require_equals")

    def if_then_else(self, condition, e_true, e_false):
        self.ops.append("if_then_else")

    @property
    def me(self):
        self.ops.append("me")
        return 0

    @property
    def owner(self):
        self.ops.append("owner")
        return 0

    @property
    def address(self):
        self.ops.append("address")
        return 0

    @owner.setter
    def owner(self, value):
        self.ops.append("Set owner")

    def create_new_object(self, constructor_function: Callable, *args):
        cls = get_class_that_defined_method(constructor_function)
        self.ops.append("new " + cls.__name__)

    def kill(self):
        self.ops.append("kill")

    def fresh(self):
        self.ops.append("FRESH")

    def now(self):
        self.ops.append("NOW")

    def return_expr(self, e):
        self.ops.append("return")

    def function_call(self, function: Function, *args, sender_is_self=False):
        self.ops.append(f"call {function.name}")
        return 0

    def read_field(self, field: Field) -> Any:
        self.ops.append(f"read {field.name}")
        return 0

    def write_field(self, field: Field, e):
        self.ops.append(f"write {field.name}")
