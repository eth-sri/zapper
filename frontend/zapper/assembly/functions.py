import itertools
from typing import List, Set, TYPE_CHECKING, Optional, Dict, Tuple
from enforce_typing import enforce_types

from zapper.assembly.binary_operations import BinaryOperator
from zapper.assembly.instructions.cid_instruction import CidInstruction
from zapper.assembly.instructions.kill_instruction import KillInstruction
from zapper.assembly.instructions.new_instruction import NewInstruction

from zapper.assembly.instructions.public_key_instruction import PublicKeyInstruction

from zapper.assembly.instructions.call_instruction import CallInstruction
from zapper.assembly.security import AssemblySecurityException
from zapper.assembly.instructions import Instruction, LoadInstruction, StoreInstruction, MoveInstruction, \
    WriteInstruction, BinaryOperationInstruction, RequireInstruction
from zapper.assembly.references import QualifiedReference
from zapper.lang.types import is_reference, is_address, Uint, is_uint, is_long
from zapper.utils.general import get_duplicates
from zapper.assembly.values import Register, FieldReference, Constant

if TYPE_CHECKING:
    from zapper.assembly.assembly_class import AssemblyClass
    from zapper.assembly.assembly_storage import AssemblyStorage


class AssemblyFunction:

    @enforce_types
    def __init__(
            self,
            function_name: str,
            instructions: List[Instruction],
            me_register: Register,
            argument_registers: List[Register],
            return_register: Register,
            is_constructor: bool = False,
            is_private: bool = False,
            is_private_for: Optional[str] = None
    ):
        self.assembly_class: Optional['AssemblyClass'] = None
        self.function_name = function_name
        self.instructions = instructions
        self.runtime_type_check_instructions: List[Instruction] = []
        self.me_register = me_register
        self.argument_registers = argument_registers
        self.return_register = return_register
        self.is_constructor = is_constructor
        self.is_private = is_private
        self.is_private_for = is_private_for

    ###########
    # LINKING #
    ###########

    def link(self, assembly_storage: 'AssemblyStorage'):
        for reg in self.argument_registers:
            if not is_address(reg.assembly_type) and not is_uint(reg.assembly_type) and not is_long(reg.assembly_type):
                if reg.assembly_type not in assembly_storage.assembly_classes:
                    raise AssemblySecurityException(
                        f"Unknown type '{reg.assembly_type}' of argument '{reg.label}' in function '{self.function_name}' of '{self.assembly_class.qualified_name}'")

        for i in self.instructions:
            if isinstance(i, LoadInstruction) or isinstance(i, StoreInstruction):
                field_reference = i.field
                assert isinstance(field_reference, FieldReference)
                field = field_reference.field
                if isinstance(field, QualifiedReference):
                    field_to_link = assembly_storage[field.qualified_class_name].get_field(field.name)
                    field_reference.field = field_to_link

            from zapper.assembly.instructions.call_instruction import CallInstruction
            if isinstance(i, CallInstruction):
                call = i.function
                if isinstance(call, QualifiedReference):
                    function_to_link = assembly_storage[call.qualified_class_name].get_function(call.name)
                    i.function = function_to_link

            if isinstance(i, NewInstruction):
                class_to_link = assembly_storage[i.assembly_class]
                i.link_assembly_class(class_to_link)

    ##########
    # CHECKS #
    ##########

    def infer_and_check_types(self, allow_type_change=False):
        original_return_type = self.return_register.assembly_type
        for instruction in self.instructions:
            instruction.infer_and_check_types(allow_type_change=allow_type_change)

        actual_return_type = self.return_register.assembly_type
        if actual_return_type != original_return_type:
            msg = f'Return register has incorrect type annotation {original_return_type} instead of {actual_return_type}'
            raise ValueError(msg)

    def check_access_policy(self, assembly_storage: 'AssemblyStorage'):
        this_class = self.assembly_class.qualified_name

        for i in self.instructions:
            if isinstance(i, StoreInstruction):
                target_class = i.target_object_id.assembly_type
                if this_class != target_class:
                    raise AssemblySecurityException(f'Trying to write to field of class {target_class} from {this_class}')

            if isinstance(i, CallInstruction):
                function = i.function
                assert isinstance(function, AssemblyFunction)
                if function.is_private:
                    target_class = function.assembly_class.qualified_name
                    if function.is_private_for is None and this_class != target_class:
                        msg = f'Trying to call private function {function.function_name} in {target_class} from {this_class}'
                        raise AssemblySecurityException(msg)
                    if function.is_private_for is not None and this_class != function.is_private_for:
                        msg = f'Trying to call private function {function.function_name} in {target_class} from {this_class}, but this is private for {function.is_private_for}'
                        raise AssemblySecurityException(msg)

            if isinstance(i, NewInstruction):
                target_class = i.assembly_class.qualified_name
                if this_class != target_class:
                    msg = f'Trying to create new {target_class} object from {this_class}'
                    raise AssemblySecurityException(msg)

            if isinstance(i, WriteInstruction):
                if i.destination == self.me_register:
                    raise AssemblySecurityException('Trying to overwrite "me"')

            if isinstance(i, StoreInstruction):
                assert isinstance(i.field, FieldReference), f'Got {type(i.target_object_id)}'
                from zapper.assembly.fields import AssemblyField
                assert isinstance(i.field.field, AssemblyField)
                if i.field.field.field_name == 'owner':
                    if not self.is_constructor:
                        if self.assembly_class.has_address:
                            raise AssemblySecurityException('Trying to change the owner of a class with an address')

            if isinstance(i, PublicKeyInstruction):
                assembly_type = i.object_id.assembly_type
                assert isinstance(assembly_type, str)
                assembly_class = assembly_storage.assembly_classes[assembly_type]
                if not assembly_class.has_address:
                    msg = f'Trying to access the address of class {assembly_class.qualified_name}.'
                    msg += ' Maybe annotate the class as has_address?'
                    raise AssemblySecurityException(msg)

            if isinstance(i, KillInstruction):
                target_class = i.object_id.assembly_type
                if this_class != target_class:
                    msg = f'Trying to kill object of class {target_class} from {this_class}'
                    raise AssemblySecurityException(msg)

    def check_register_labels(self):
        """
        Check that:
        - Register labels do not contain dots
        - Register labels are unique within this function
        """
        registers = self.get_registers()
        names = [r.label for r in registers]

        with_dot = [n for n in names if '.' in names]
        if len(with_dot) > 0:
            raise AssemblySecurityException('Register labels with dots: ' + ' '.join(with_dot))

        duplicates = get_duplicates(names)
        if len(duplicates) > 0:
            raise AssemblySecurityException('Register labels are not unique: ' + ' '.join(duplicates))

    def check_constructor(self):
        # first, check whether NEW does not occur at any position other than 0 (required for the following check)
        for i in range(1, len(self.instructions)):
            if isinstance(self.instructions[i], NewInstruction):
                raise AssemblySecurityException('NEW instruction must be first instruction in instruction list')

        if isinstance(self.instructions[0], NewInstruction):
            # if the first instruction is NEW, this is a constructor function
            # we check whether all fields are initialized (this is relevant for type safety)
            self._check_all_fields_initialized_for(self.instructions[0].destination, self.instructions)

    def _check_all_fields_initialized_for(self, self_register: Register, instructions: List['Instruction']):
        # find all fields of self that are written
        written_fields = set()
        for i in instructions:
            if isinstance(i, StoreInstruction):
                if i.target_object_id == self_register:
                    written_fields.add(i.field.field.field_name)

        # check whether all fields are written
        for field_name in self.assembly_class.fields.keys():
            if field_name not in written_fields:
                raise AssemblySecurityException(
                    f"Field '{field_name}' not initialized in constructor '{self.function_name}' of class '{self.assembly_class.qualified_name}'")

    def insert_runtime_checks(self, class_to_id: Dict[str, int]):
        # insert runtime type checks for contract-type arguments
        checks: List[Instruction] = []
        i = 0
        for reg in self.argument_registers:
            if is_uint(reg.assembly_type):
                # insert "+0" in order to ensure the value of the register is in [0, 2^120-1]
                checks.append(BinaryOperationInstruction(BinaryOperator.PLUS, reg, reg, Constant(0, Uint)))
            elif not is_address(reg.assembly_type) and not is_uint(reg.assembly_type) and not is_long(reg.assembly_type):
                expected_cid = class_to_id[reg.assembly_type]
                cid_register = Register(f'cid-check-{i}')
                checks.append(CidInstruction(cid_register, reg))
                checks.append(BinaryOperationInstruction(BinaryOperator.EQUALS, cid_register, cid_register, Constant(expected_cid, Uint)))
                checks.append(RequireInstruction(cid_register))
                i += 1
        self.runtime_type_check_instructions = checks

    ############
    # INLINING #
    ############

    def get_called_function_names(self) -> Set[Tuple[str, str]]:
        called = set()
        for i, instruction in enumerate(self.instructions):
            if isinstance(instruction, CallInstruction):
                called_function = instruction.function
                assert isinstance(called_function, AssemblyFunction)
                called.add((called_function.assembly_class.qualified_name, called_function.function_name))
        return called

    def inline(self, assembly_storage: 'AssemblyStorage'):
        all_inlined = []
        for i, instruction in enumerate(self.instructions):
            if isinstance(instruction, CallInstruction):
                called_function = instruction.function
                assert isinstance(called_function, AssemblyFunction)

                # get latest instructions from assembly storage as child calls may have been inlined
                called_function_inlined = assembly_storage.assembly_classes[called_function.assembly_class.qualified_name].get_function(called_function.function_name)
                called_function = called_function_inlined.clone_for_inlining('inlined#' + str(i))

                # handle "me"
                if instruction.sender_is_self:
                    key = PublicKeyInstruction(called_function.me_register, self.argument_registers[0])
                    all_inlined.append(key)
                else:
                    move = MoveInstruction(called_function.me_register, self.me_register)
                    all_inlined.append(move)

                # handle parameters
                for parameter, argument in zip(called_function.argument_registers, instruction.call_arguments):
                    move = MoveInstruction(parameter, argument)
                    all_inlined.append(move)

                # handle body
                all_inlined += called_function.instructions

                # handle return value
                move = MoveInstruction(instruction.destination, called_function.return_register)
                all_inlined.append(move)

            else:
                all_inlined.append(instruction)

        fun = AssemblyFunction(
            self.function_name,
            all_inlined,
            self.me_register,
            self.argument_registers,
            self.return_register,
            self.is_constructor,
            self.is_private,
            self.is_private_for
        )
        fun.assembly_class = self.assembly_class
        return fun

    def clone_for_inlining(self, register_postfix: Optional[str], register_mapping: Dict[Register, Register] = None):
        if register_mapping is None:
            register_mapping = {}

        new_me = self.me_register.clone(register_postfix)
        new_argument_registers = [r.clone(register_postfix) for r in self.argument_registers]
        new_return_register = self.return_register.clone(register_postfix)

        mapping = dict(zip(self.argument_registers, new_argument_registers))
        mapping[self.me_register] = new_me
        mapping[self.return_register] = new_return_register
        mapping.update(register_mapping)

        new_instructions = []
        for instruction in self.instructions:
            new_instruction = instruction.get_inlined_equivalent(mapping, register_postfix)
            new_instructions.append(new_instruction)

        return AssemblyFunction(
            self.function_name,
            new_instructions,
            new_me,
            new_argument_registers,
            new_return_register,
            self.is_constructor,
            self.is_private,
            self.is_private_for
        )

    ###########
    # HELPERS #
    ###########

    def get_all_instructions(self) -> List[Instruction]:
        return self.runtime_type_check_instructions + self.instructions

    def get_registers(self) -> Set['Register']:
        register_lists = [i.get_registers() for i in self.get_all_instructions()]
        all_registers = set(itertools.chain(*register_lists))
        all_registers.add(self.me_register)
        return all_registers

    def __str__(self):
        arguments = ', '.join([a.str_with_type() for a in self.argument_registers])
        instructions = '\n'.join(['    ' + str(i) for i in self.get_all_instructions()])
        return f'def {self.function_name}({arguments}) -> {self.return_register.str_with_type()}:\n{instructions}'
