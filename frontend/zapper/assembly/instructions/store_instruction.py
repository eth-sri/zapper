from zapper.assembly.instructions.instruction import Instruction
from zapper.assembly.types import check_assembly_supertype
from zapper.assembly.values import Register, Value, PseudoConstant


class StoreInstruction(Instruction):

    def __init__(self, source: Register, target_object_id: Value, field: PseudoConstant):
        super().__init__(source, target_object_id, field)

    #################
    # TYPE CHECKING #
    #################

    def infer_and_check_types(self, allow_type_change=False):
        check_assembly_supertype(self.field.assembly_type, self.source.assembly_type, stack=self.stack)

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 5

    @property
    def opcode_str(self):
        return 'STORE'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def source(self):
        return self.register

    @property
    def target_object_id(self):
        return self.value_1

    @property
    def field(self):
        return self.value_2



