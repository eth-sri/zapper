from zapper.assembly.instructions.write_instruction import WriteInstruction
from zapper.assembly.types import AssemblyTypeError
from zapper.assembly.values import Register, Value
from zapper.lang.types import is_uint


class ConditionalMoveInstruction(WriteInstruction):

    def __init__(self, destination: Register, condition: Value, source: Value):
        super().__init__(destination, condition, source)

    #################
    # TYPE CHECKING #
    #################

    def check_argument_types(self):
        if self.destination.assembly_type != self.source.assembly_type:
            raise AssemblyTypeError("Types must match for CMOV", self.stack)
        if not is_uint(self.condition.assembly_type):
            raise AssemblyTypeError("Condition of CMOV must be a boolean value", self.stack)

    def infer_written_type(self):
        return self.source.assembly_type

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 2

    @property
    def opcode_str(self):
        return 'CMOV'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def condition(self):
        return self.value_1

    @property
    def source(self):
        return self.value_2


