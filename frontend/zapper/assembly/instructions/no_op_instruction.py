from zapper.assembly.instructions.instruction import Instruction


class NoOpInstruction(Instruction):

    def __init__(self):
        super().__init__(None, None, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_and_check_types(self, allow_type_change=False):
        pass

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 0

    @property
    def opcode_str(self):
        return 'NOOP'
