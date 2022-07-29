from typing import Type, List

from zapper.assembly.instructions import MoveInstruction, Instruction, StoreInstruction
from zapper.assembly.instructions.new_instruction import NewInstruction

from zapper.compiler.assembly_emitter_observer import AssemblyEmitterObserver, ensure_expression_observer
from zapper.compiler.instruction_builder import InstructionBuilder
from zapper.assembly.values import Register
from zapper.lang.field import Field
from zapper.assembly.fields import AssemblyField
from zapper.assembly.functions import AssemblyFunction
from zapper.assembly.types import zapper_type_to_assembly_type
from zapper.lang.function import Function
from zapper.utils.inspection import get_qualified_name
from zapper.assembly.assembly_class import AssemblyClass
from zapper.lang.contract import Contract


def compile_contract(contract: Type[Contract]):
    qualified_name = get_qualified_name(contract)
    compiled = AssemblyClass(qualified_name, contract.has_address)

    for field in contract.zapper_fields.values():
        assembly_field = zapper_field_to_assembly_field(field)
        compiled.add_field(assembly_field)

    for function in contract.zapper_functions.values():
        assembly_function = zapper_function_to_assembly_function(function, compiled)
        compiled.add_function(assembly_function)

    return compiled


##########
# FIELDS #
##########


def zapper_field_to_assembly_field(field: Field):
    field_type = zapper_type_to_assembly_type(field.zapper_type)
    assembly_field = AssemblyField(field.name, field_type)
    return assembly_field


#############
# FUNCTIONS #
#############


def zapper_function_to_assembly_function(function: Function, partial_class: AssemblyClass):
    name = function.name
    builder = InstructionBuilder()
    argument_observers = get_argument_observers(function, builder)

    self = argument_observers[0].value
    if function.is_constructor:
        # initialize "self" with new object
        assert isinstance(self, Register)
        new_type = zapper_type_to_assembly_type(function.contract_type)
        new = NewInstruction(self, new_type)
        builder.append(new)

    function_code = getattr(function.contract_type, function.name)
    ret = function_code(*argument_observers)

    # handle return value
    return_register = Register('return')
    return_register.assembly_type = zapper_type_to_assembly_type(function.return_type)
    if ret is None:
        if function.is_constructor:
            ret = argument_observers[0]
        else:
            ret = 0
    ret = ensure_expression_observer(ret)
    i = MoveInstruction(return_register, ret.value)
    builder.append(i)

    me_register = builder.me_register
    argument_registers = [o.value for o in argument_observers]
    if function.is_constructor:
        # remove "self" from argument registers
        argument_registers = argument_registers[1:]

    assembly_function = AssemblyFunction(
        name,
        builder.instructions,
        me_register,
        argument_registers,
        return_register,
        function.is_constructor,
        function.is_private,
        function.is_private_for
    )
    return assembly_function


def get_argument_observers(function: Function, builder: InstructionBuilder):
    argument_observers = []
    for name, t in function.argument_types.items():
        register = Register(name)
        register.assembly_type = zapper_type_to_assembly_type(t)

        o = AssemblyEmitterObserver(register, t, builder)
        argument_observers.append(o)
    return argument_observers
