from zapper.lang.types import Address
from zapper.assembly.instructions import WriteInstruction
from zapper.assembly.types import AssemblyType
from zapper.assembly.values import Register, Value


class PublicKeyInstruction(WriteInstruction):

    def __init__(self, destination: Register, object_id: Value):
        super().__init__(destination, object_id, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_written_type(self) -> AssemblyType:
        return Address

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 7

    @property
    def opcode_str(self):
        return 'PK'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def object_id(self):
        return self.value_1
