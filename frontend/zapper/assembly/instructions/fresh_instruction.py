from zapper.lang.types import Long
from zapper.assembly.instructions import WriteInstruction
from zapper.assembly.types import AssemblyType
from zapper.assembly.values import Register


class FreshInstruction(WriteInstruction):

    def __init__(self, destination: Register):
        super().__init__(destination, None, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_written_type(self) -> AssemblyType:
        return Long

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 10

    @property
    def opcode_str(self):
        return 'FRESH'
