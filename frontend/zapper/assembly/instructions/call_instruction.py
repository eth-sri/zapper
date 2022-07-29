from typing import List, TYPE_CHECKING, Union

from zapper.assembly.instructions.write_instruction import WriteInstruction
from zapper.assembly.references import QualifiedReference
from zapper.assembly.types import check_assembly_supertype, AssemblyTypeError

if TYPE_CHECKING:
    from zapper.assembly.values import Register, Value
    from zapper.assembly.functions import AssemblyFunction


class CallInstruction(WriteInstruction):

    def __init__(
            self,
            destination: 'Register',
            function: Union['AssemblyFunction', QualifiedReference],
            call_arguments: List['Value'],
            sender_is_self: bool
    ):
        super().__init__(destination, None, None)
        self.function = function
        self.call_arguments = call_arguments
        self.sender_is_self = sender_is_self

    def get_arguments(self):
        return [self.destination] + self.call_arguments

    #################
    # TYPE CHECKING #
    #################

    def check_argument_types(self):
        n_expected_arguments = len(self.function.argument_registers)
        n_actual_arguments = len(self.call_arguments)
        if n_expected_arguments != n_actual_arguments:
            msg = f'Incorrect number of arguments ({n_actual_arguments} instead of {n_expected_arguments})'
            raise AssemblyTypeError(msg, self.stack)

        for expected, actual in zip(self.function.argument_registers, self.call_arguments):
            check_assembly_supertype(expected.assembly_type, actual.assembly_type, self.stack)

    def infer_written_type(self):
        return self.function.return_register.assembly_type

    ##########
    # OPCODE #
    ##########

    @property
    def opcode(self):
        return None

    @property
    def opcode_str(self):
        return 'CALL'

    ###########
    # HELPERS #
    ###########

    def function_name(self):
        if isinstance(self.function, QualifiedReference):
            return self.function.qualified_class_name + '.' + self.function.name
        else:
            return self.function.assembly_class.qualified_name + '.' + self.function.function_name

    def __str__(self):
        arguments = ['_' if a is None else str(a) for a in self.get_arguments()]
        arguments = ' '.join(arguments)
        return self.opcode_str + ' ' + self.function_name() + ' ' + arguments
