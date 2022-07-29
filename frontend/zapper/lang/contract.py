from typing import Callable, Dict, Type

from zapper.utils.general import order_dictionary_by_keys
from zapper.lang.field import Field, extract_field
from zapper.lang.function import Function, extract_function
from zapper.lang.type_address import Address
from zapper.utils.inspection import get_member_names_no_superclass
from zapper.zapper_logging import getLogger

logger = getLogger(__name__)


def constructor(f: Callable):
    f.is_constructor = True
    return f


def internal(f: Callable):
    f.is_private = True
    return f


def only(qualified_class_name: str):
    def inner(f: Callable):
        f.is_private = True
        f.is_private_for = qualified_class_name
        return f
    return inner


def has_address(c: Type['Contract']):
    c.has_address = True
    return c


class Contract:
    """
    Base class for contracts.

    Contract fields:
    - Should be declared as class attributes

    Contract functions:
    - Should be declared as functions on subclasses
    - Functions annotated as "@constructor" are constructors
    """

    has_address = False

    # ----- to be used in subclasses -----

    def require(self, e):
        """
        Abort if e does not hold
        """
        pass

    def require_equals(self, e1, e2):
        """
        Abort if e1 != e2
        """
        pass

    def if_then_else(self, condition, e_true, e_false):
        """
        Ternary operator "condition ? e_true : e_false"
        """
        pass

    @property
    def me(self) -> 'Address':
        """
        Caller address (user or contract)
        """
        pass

    @property
    def address(self) -> 'Address':
        """
        Address of the "self" object
        """
        pass

    @property
    def owner(self) -> 'Address':
        """
        Owner of the current object
        """
        pass

    @owner.setter
    def owner(self, value):
        """
        Set the owner of the current object
        """
        pass

    def create_new_object(self, constructor_function: Callable, *args):
        """
        Args:
            constructor_function: Function used to construct the new object
            *args:
            **kwargs:
        """
        pass

    def kill(self):
        """
        Kill/delete the current object
        """
        pass

    def fresh(self):
        """
        Returns a freshly derived, unique secret value
        """
        pass

    def now(self):
        """
        Returns the current timestamp
        """
        pass

    # ----- internals -----

    zapper_fields: Dict[str, Field]
    zapper_functions: Dict[str, Function]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # ensure subclass does not re-declare existing members
        members_here = get_member_names_no_superclass(cls, include_fields=True, include_functions=True)
        members_super = get_member_names_no_superclass(Contract, include_fields=True, include_functions=True)
        members_both = [m for m in members_here if m in members_super]
        if len(members_both) > 0:
            raise AssertionError(f"Contract '{cls.__name__}' must not re-declare internal member '{members_both[0]}'")

        cls.zapper_fields = cls.__extract_zapper_fields__()
        cls.zapper_fields["owner"] = Field(cls, "owner", Address)   # add implicit owner field
        cls.zapper_functions = cls.__extract_zapper_functions__()

    @classmethod
    def __extract_zapper_fields__(cls):
        fields = get_member_names_no_superclass(cls, include_fields=True, include_functions=False)
        zapper_fields = {
            name: extract_field(cls, name) for name in fields
        }
        return order_dictionary_by_keys(zapper_fields)

    @classmethod
    def __extract_zapper_functions__(cls):
        functions = get_member_names_no_superclass(cls, include_fields=False, include_functions=True)

        exclude = ['zapper_fields', 'zapper_functions']
        functions = [f for f in functions if f not in exclude]

        zapper_functions = {
            name: extract_function(cls, name) for name in functions
        }
        return order_dictionary_by_keys(zapper_functions)
