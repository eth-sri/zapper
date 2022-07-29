from abc import ABC, abstractmethod
from typing import Optional

from zapper.assembly.instructions.instruction import Instruction
from zapper.assembly.types import AssemblyType, check_assembly_supertype, is_assembly_type
from zapper.assembly.values import Register, Value


class WriteInstruction(Instruction, ABC):
    """
    Abstract class representing various writing instructions
    """

    def __init__(self, destination: Optional[Register], value_1: Optional[Value], value_2: Optional[Value]):
        super().__init__(destination, value_1, value_2)

    #################
    # TYPE CHECKING #
    #################

    @abstractmethod
    def infer_written_type(self) -> AssemblyType:
        """

        Returns: the type of the value to be written

        """
        raise NotImplementedError()

    def check_argument_types(self):
        """
        Check whether the inputs/arguments have valid types
        """
        pass

    def infer_and_check_types(self, allow_type_change=False):
        self.check_argument_types()

        written_type = self.infer_written_type()
        if not is_assembly_type(written_type):
            raise ValueError(f'Unexpected type {written_type}')

        if allow_type_change or self.destination.assembly_type is None:
            self.destination.assembly_type = written_type
        else:
            check_assembly_supertype(self.destination.assembly_type, written_type, stack=self.stack)

    ######################
    # CONVENIENCE FIELDS #
    ######################

    @property
    def destination(self):
        return self.register
