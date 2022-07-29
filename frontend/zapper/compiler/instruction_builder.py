from typing import List

from zapper.lang.types import Address, ZapperType

from zapper.assembly.instructions import Instruction
from zapper.assembly.values import Register


class InstructionBuilder:

    def __init__(self):
        self.next_register_index = 0
        self.instructions: List[Instruction] = []

        self.me_register = Register('me')
        self.me_register.assembly_type = Address

    def append(self, instruction: Instruction):
        self.instructions.append(instruction)

    def next_register(self, prefix: str):
        self.next_register_index += 1
        label = prefix + '#' + str(self.next_register_index)
        register = Register(label)
        return register
