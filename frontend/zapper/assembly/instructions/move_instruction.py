from zapper.assembly.instructions.write_instruction import WriteInstruction

from zapper.assembly.values import Register, Value


class MoveInstruction(WriteInstruction):

    def __init__(self, destination: Register, source: Value):
        super().__init__(destination, source, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_written_type(self):
        return self.source.assembly_type

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 1

    @property
    def opcode_str(self):
        return 'MOV'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def source(self):
        return self.value_1
