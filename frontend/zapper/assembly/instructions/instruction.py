import traceback
from abc import abstractmethod, ABC
from typing import Optional, List, Dict

from zapper.assembly.values import Value, Register


class Instruction(ABC):

    def __init__(self, register: Optional[Register], value_1: Optional[Value], value_2: Optional[Value]):
        self.register = register
        self.value_1 = value_1
        self.value_2 = value_2
        self.stack = traceback.extract_stack()

    #################
    # TYPE CHECKING #
    #################

    @abstractmethod
    def infer_and_check_types(self, allow_type_change=False):
        pass

    ############
    # INLINING #
    ############

    def get_inlined_equivalent(self, mapping: Dict[Register, Register], postfix: str):
        empty = self.__class__.__new__(self.__class__)
        for key, value in vars(self).items():
            if isinstance(value, Register):
                if value in mapping:
                    new_value = mapping[value]
                else:
                    new_value = value.clone(postfix)
                    mapping[value] = new_value
            else:
                new_value = value
            setattr(empty, key, new_value)
        return empty

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self) -> int:
        raise NotImplementedError()

    @property
    def opcode_str(self) -> str:
        raise NotImplementedError()

    ###########
    # HELPERS #
    ###########

    def get_arguments(self):
        return [self.register, self.value_1, self.value_2]

    def get_registers(self) -> List[Register]:
        return [a for a in self.get_arguments() if isinstance(a, Register)]

    def __str__(self):
        arguments = ['_' if a is None else str(a) for a in self.get_arguments()]
        arguments = ' '.join(arguments)
        return self.opcode_str + ' ' + arguments
