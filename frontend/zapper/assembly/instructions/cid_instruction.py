from zapper.lang.types import Long
from zapper.assembly.instructions import WriteInstruction
from zapper.assembly.types import AssemblyType
from zapper.assembly.values import Register, Value


class CidInstruction(WriteInstruction):

    def __init__(self, destination: Register, object_id: Value):
        super().__init__(destination, object_id, None)

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
        return 9

    @property
    def opcode_str(self):
        return 'CID'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def object_id(self):
        return self.value_1
