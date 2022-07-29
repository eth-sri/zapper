from zapper.lang.types import Uint
from zapper.assembly.instructions import WriteInstruction
from zapper.assembly.types import AssemblyType
from zapper.assembly.values import Register


class NowInstruction(WriteInstruction):

    def __init__(self, destination: Register):
        super().__init__(destination, None, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_written_type(self) -> AssemblyType:
        return Uint

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 11

    @property
    def opcode_str(self):
        return 'NOW'
