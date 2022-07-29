from zapper.assembly.instructions.write_instruction import WriteInstruction
from zapper.assembly.values import Register, Value, PseudoConstant


class LoadInstruction(WriteInstruction):

    def __init__(self, destination: Register, object_id: Value, field: PseudoConstant):
        super().__init__(destination, object_id, field)

    #################
    # TYPE CHECKING #
    #################

    def infer_written_type(self):
        return self.field.assembly_type

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 4

    @property
    def opcode_str(self):
        return 'LOAD'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def object_id(self):
        return self.value_1

    @property
    def field(self):
        return self.value_2
