from abc import ABC
from typing import Union, TYPE_CHECKING, Optional

from zapper.lang.types import Uint, Address, is_uint, is_address, Long, is_long, is_uint_literal
from zapper.assembly.types import AssemblyType, assembly_type_to_str, is_assembly_type

if TYPE_CHECKING:
    from zapper.assembly.assembly_class import AssemblyClass
    from zapper.assembly.fields import AssemblyField
    from zapper.assembly.references import QualifiedReference


class Value(ABC):
    """
    A register or a (pseudo-)constant
    """

    def __init__(self):
        # The type of this value, where the type of an object_id is the type of the object it points to
        self.assembly_type: AssemblyType = None

    def has_type(self):
        return self.assembly_type is not None


class Register(Value):

    def __init__(self, label: Union[str, int]):
        super().__init__()
        self.label = label
        self.location = -1

    def __str__(self):
        return self.label

    def str_with_type(self):
        ret = ''
        if self.has_type():
            ret += assembly_type_to_str(self.assembly_type) + ' '
        ret += str(self)
        return ret

    def clone(self, postfix: Optional[str] = None):
        """

        @param postfix: If none, return self, otherwise return a cloned version with this postfix
        @return:
        """
        if postfix is None:
            return self
        else:
            return Register(self.label + '#' + postfix)


class PseudoConstant(Value, ABC):
    """
    See subclasses
    """
    pass


class Constant(PseudoConstant):
    """
    An actual constant
    """

    def __init__(self, value: Uint | Long | Address, assembly_type: AssemblyType):
        super().__init__()

        # cannot check for Uint / Address / Long due to Python restrictions
        assert isinstance(value, int)
        assert is_uint(assembly_type) or is_address(assembly_type) or is_long(assembly_type)

        if is_uint(assembly_type):
            assert is_uint_literal(value)

        self.value = value
        self.assembly_type = assembly_type

    def __str__(self):
        return str(self.value)


class FieldReference(PseudoConstant):
    """
    A field reference that can be translated to its offset
    """

    def __init__(self, field: Union['AssemblyField', 'QualifiedReference']):
        super().__init__()
        self.field = field
        self.assembly_type = self.field.field_type

        from zapper.assembly.fields import AssemblyField
        from zapper.assembly.references import QualifiedReference
        assert isinstance(field, AssemblyField) or isinstance(field, QualifiedReference)
        assert is_assembly_type(self.assembly_type)

    def __str__(self):
        from zapper.assembly.fields import AssemblyField
        from zapper.assembly.references import QualifiedReference

        if isinstance(self.field, AssemblyField):
            return self.field.field_name
        else:
            assert isinstance(self.field, QualifiedReference)
            return self.field.name


class ClassReference(PseudoConstant):
    """
    A class reference that can be translated to its class id
    """

    def __init__(self, assembly_class: Union['AssemblyClass', str]):
        super().__init__()
        self.assembly_class = assembly_class
        self.assembly_type = None

    def __str__(self):
        if isinstance(self.assembly_class, str):
            return self.assembly_class
        else:
            return self.assembly_class.qualified_name
