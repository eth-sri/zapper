from typing import Callable
from unittest import TestCase

from zapper.assembly.instructions.call_instruction import CallInstruction

from zapper.assembly.assembly_class import AssemblyClass
from zapper.assembly.fields import AssemblyField
from zapper.assembly.binary_operations import BinaryOperator
from zapper.lang.types import Uint, Address
from zapper.assembly.functions import AssemblyFunction
from zapper.assembly.instructions import MoveInstruction, BinaryOperationInstruction, NoOpInstruction, LoadInstruction, \
    StoreInstruction
from zapper.assembly.values import Register, FieldReference


me = Register('me')
me.assembly_type = Address


def get_simple_function():
    arg = Register('arg')
    arg.assembly_type = 'Class'

    ret = Register('return')
    ret.assembly_type = 'Class'

    instruction = MoveInstruction(ret, arg)
    function = AssemblyFunction('f', [instruction], me, [arg], ret)

    return function


simple_function_str = """
def f(Class arg) -> Class return:
    MOV return arg _
""".strip()


def get_addition_function():
    arg1 = Register('arg1')
    arg1.assembly_type = Uint

    arg2 = Register('arg2')
    arg2.assembly_type = Uint

    ret = Register('return')
    ret.assembly_type = Uint

    instruction = BinaryOperationInstruction(BinaryOperator.PLUS, ret, arg1, arg2)
    function = AssemblyFunction('f', [instruction, NoOpInstruction()], me, [arg1, arg2], ret)

    return function


addition_function_str = """
def f(uint arg1, uint arg2) -> uint return:
    BinaryOperator.PLUS return arg1 arg2
    NOOP _ _ _
""".strip()


def get_load_store_function():
    # classes
    c = AssemblyClass('C', False)
    d = AssemblyClass('D', False)

    # fields
    c_to_d_field = AssemblyField('c_to_d', d.qualified_name)
    c.add_field(c_to_d_field)

    d_to_c_field = AssemblyField('d_to_c', c.qualified_name)
    d.add_field(d_to_c_field)

    # registers
    arg = Register('arg')
    arg.assembly_type = c.qualified_name

    ret = Register('ret')
    ret.assembly_type = d.qualified_name

    # instructions
    load = LoadInstruction(ret, arg, FieldReference(c_to_d_field))  # ret = arg.c_to_d
    store = StoreInstruction(arg, ret, FieldReference(d_to_c_field))

    # function
    function = AssemblyFunction('f', [load, store], me, [arg], ret)
    return function


load_store_function_str = """
def f(C arg) -> D ret:
    LOAD ret arg c_to_d
    STORE arg ret d_to_c
""".strip()


def get_call_function():
    # parent class
    c = AssemblyClass('C', False)

    # simple identity function

    arg = Register('arg_callee')
    arg.assembly_type = c.qualified_name

    ret = Register('return_callee')
    ret.assembly_type = c.qualified_name

    move = MoveInstruction(ret, arg)
    callee = AssemblyFunction('callee', [move], me, [arg], ret)
    callee.assembly_class = c

    # simple call function

    arg = Register('arg_caller')
    arg.assembly_type = c.qualified_name

    ret = Register('return_caller')
    ret.assembly_type = c.qualified_name

    call = CallInstruction(ret, callee, [arg], False)
    caller = AssemblyFunction('caller', [call], me, [arg], ret)
    caller.assembly_class = c

    return caller


call_function_str = """
def caller(C arg_caller) -> C return_caller:
    CALL C.callee return_caller arg_caller
""".strip()


class Wrapper:
    # needs a wrapper to prevent trying to test this function directly

    class AbstractTestAssembly(TestCase):

        def __init__(self, get_assembly: Callable[[], AssemblyFunction], assembly_str: str, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.assembly = get_assembly()
            self.assembly_str = assembly_str

        def test_infer_and_check_types(self):
            self.assembly.infer_and_check_types()

        def test_check_register_labels(self):
            self.assembly.check_register_labels()

        def test_string(self):
            self.assertEqual(str(self.assembly), self.assembly_str)


class TestSimple(Wrapper.AbstractTestAssembly):

    def __init__(self, *args, **kwargs):
        super().__init__(get_simple_function, simple_function_str, *args, **kwargs)


class TestAddition(Wrapper.AbstractTestAssembly):

    def __init__(self, *args, **kwargs):
        super().__init__(get_addition_function, addition_function_str, *args, **kwargs)


class TestLoadStore(Wrapper.AbstractTestAssembly):

    def __init__(self, *args, **kwargs):
        super().__init__(get_load_store_function, load_store_function_str, *args, **kwargs)


class TestCall(Wrapper.AbstractTestAssembly):

    def __init__(self, *args, **kwargs):
        super().__init__(get_call_function, call_function_str, *args, **kwargs)
