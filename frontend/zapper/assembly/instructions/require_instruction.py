from zapper.assembly.instructions.instruction import Instruction
from zapper.assembly.values import Value

from zapper.lang.types import Uint

from zapper.assembly.types import check_assembly_supertype


class RequireInstruction(Instruction):

    def __init__(self, condition: Value):
        super().__init__(None, condition, None)

    #################
    # TYPE CHECKING #
    #################

    def infer_and_check_types(self, allow_type_change=False):
        check_assembly_supertype(Uint, self.condition.assembly_type, stack=self.stack)

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 3

    @property
    def opcode_str(self):
        return 'REQ'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def condition(self):
        return self.value_1

