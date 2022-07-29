from zapper.assembly.types import AssemblyTypeError
from zapper.lang.types import Uint, is_uint

from zapper.assembly.binary_operations import BinaryOperator
from zapper.assembly.instructions.write_instruction import WriteInstruction
from zapper.assembly.values import Register, Value

n_opcodes_before_binary = 12


class BinaryOperationInstruction(WriteInstruction):

    def __init__(self, op: BinaryOperator, destination: Register, value_1: Value, value_2: Value):
        super().__init__(destination, value_1, value_2)
        self.op = op

    #################
    # TYPE CHECKING #
    #################

    def check_argument_types(self):
        if self.op in [BinaryOperator.EQUALS]:
            if self.value_1.assembly_type != self.value_2.assembly_type:
                raise AssemblyTypeError("Types should match for ==", self.stack)
        else:
            if not is_uint(self.value_1.assembly_type) or not is_uint(self.value_2.assembly_type):
                raise AssemblyTypeError("Binary operations +-*>< only supported for uint", self.stack)

    def infer_written_type(self):
        return Uint

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        if self.op >= 0:
            return n_opcodes_before_binary + int(self.op)
        else:
            return None

    @property
    def opcode_str(self):
        return str(BinaryOperator(self.op))
