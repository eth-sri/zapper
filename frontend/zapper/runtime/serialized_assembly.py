from typing import Optional, TYPE_CHECKING

from zapper.assembly.assembly_class import AssemblyClass
from zapper.assembly.fields import AssemblyField
from zapper.assembly.instructions.call_instruction import CallInstruction
from zapper.assembly.values import Value, Register, Constant, ClassReference, FieldReference
from zapper.utils.general import to_hex_str

if TYPE_CHECKING:
    from zapper.assembly.instructions.instruction import Instruction
    from zapper.assembly.functions import AssemblyFunction


class SerializedInstruction:
    """
    A low-level serialized instruction representation for the backend processor.
    The sources are converted to hex strings as otherwise, large integers will fail to convert to
    backend integers.
    """

    def __init__(self, opcode: int, dst: int, src_1: int, src_1_is_const: bool, src_2: int, src_2_is_const: bool):
        assert(opcode >= 0 and dst >= 0 and src_1 >= 0 and src_2 >= 0)
        self.opcode: int = opcode
        self.dst: int = dst
        self.src_1: str = to_hex_str(src_1)
        self.src_1_is_const: bool = src_1_is_const
        self.src_2: str = to_hex_str(src_2)
        self.src_2_is_const: bool = src_2_is_const


def serialize_value(value: Optional[Value]) -> (int, int):
    if value is None:
        return 0, False
    if isinstance(value, Register):
        return value.location, False
    elif isinstance(value, Constant):
        return value.value, True
    elif isinstance(value, ClassReference):
        if not isinstance(value.assembly_class, AssemblyClass):
            raise AssertionError("tried to serialize non-linked class reference")
        return value.assembly_class.class_id, True
    elif isinstance(value, FieldReference):
        if not isinstance(value.field, AssemblyField):
            raise AssertionError("tried to serialize non-linked field reference")
        return value.field.location, True
    else:
        raise NotImplementedError()


def serialize_instruction(i: 'Instruction') -> SerializedInstruction:
    if isinstance(i, CallInstruction):
        raise AssertionError("tried to serialize non-inlined call instruction")
    dst = 0 if i.register is None else i.register.location
    src_1, src_1_is_const = serialize_value(i.value_1)
    src_2, src_2_is_const = serialize_value(i.value_2)
    return SerializedInstruction(i.opcode, dst, src_1, src_1_is_const, src_2, src_2_is_const)


class SerializedFunction:
    """
    A low-level serialized representation of the function for the backend processor
    """
    def __init__(self, class_id: int, function_id: int, assembly_function: 'AssemblyFunction'):
        self.class_id = class_id
        self.function_id = function_id
        self.return_register = assembly_function.return_register.location
        assert(self.return_register >= 0)
        self.instructions = [serialize_instruction(i) for i in assembly_function.get_all_instructions()]
