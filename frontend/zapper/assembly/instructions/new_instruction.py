from typing import TYPE_CHECKING, Union

from zapper.assembly.instructions import WriteInstruction
from zapper.assembly.types import AssemblyType
from zapper.assembly.values import Register, ClassReference

if TYPE_CHECKING:
    from zapper.assembly.assembly_class import AssemblyClass


class NewInstruction(WriteInstruction):

    def __init__(self, destination: Register, assembly_class: Union['AssemblyClass', str]):
        class_id = ClassReference(assembly_class)
        super().__init__(destination, class_id, None)
        self.assembly_class = assembly_class

    def link_assembly_class(self, assembly_class: 'AssemblyClass'):
        class_id = ClassReference(assembly_class)
        self.value_1 = class_id
        self.assembly_class = assembly_class

    #################
    # TYPE CHECKING #
    #################

    def infer_written_type(self) -> AssemblyType:
        return self.assembly_class.qualified_name

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return 8

    @property
    def opcode_str(self):
        return 'NEW'

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def class_id(self):
        return self.value_1
