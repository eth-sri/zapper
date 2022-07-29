from zapper.lang.types import is_reference

from zapper.assembly.instructions import Instruction
from zapper.assembly.types import AssemblyTypeError
from zapper.assembly.values import Register


class KillInstruction(Instruction):

    def __init__(self, object_id: Register):
        super().__init__(None, object_id, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_and_check_types(self, allow_type_change=False):
        t = self.object_id.assembly_type

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 6

    @property
    def opcode_str(self):
        return 'KILL'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def object_id(self):
        return self.value_1
