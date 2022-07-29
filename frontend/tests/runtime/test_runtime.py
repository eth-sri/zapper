from unittest import TestCase

from zapper_backend import trusted_setup

from zapper.assembly.binary_operations import BinaryOperator
from zapper.assembly.functions import AssemblyFunction
from zapper.assembly.instructions import BinaryOperationInstruction, NoOpInstruction
from zapper.assembly.values import Register
from zapper.lang.types import Uint, Address
from zapper.runtime.runtime import Runtime, to_hex_str
from zapper.runtime.serialized_assembly import SerializedFunction


def get_function():
    me = Register('me')
    me.assembly_type = Address
    me.location = 0

    arg1 = Register('arg1')
    arg1.assembly_type = Uint
    arg1.location = 1

    arg2 = Register('arg2')
    arg2.assembly_type = Uint
    arg2.location = 2

    ret = Register('return')
    ret.assembly_type = Uint
    ret.location = 0

    instruction = BinaryOperationInstruction(BinaryOperator.PLUS, ret, arg1, arg2)
    function = AssemblyFunction('f', [instruction, NoOpInstruction()], me, [arg1, arg2], ret)

    return SerializedFunction(77, 8, function)


class MockLedger:
    def __init__(self, crypto_params, function):
        self.crypto_params = crypto_params
        self.function = function
        self.accepted_transactions = []
        self.current_time = 5

    def get_serialized_function(self, class_name, function_name):
        return self.function

    def verify_and_execute_transaction(self, transaction):
        pass


class TestRuntime(TestCase):

    def test_call_function(self):
        crypto_params = trusted_setup(dbg_no_circuit_setup=True)
        runtime = Runtime(MockLedger(crypto_params, get_function()))
        user = runtime.new_user_account()
        ret = runtime.call_function("c", "f", user, [Uint(33), Uint(44)])
        self.assertEqual(ret, 77)

    def test_accounts(self):
        crypto_params = trusted_setup(dbg_no_circuit_setup=True)
        runtime_1 = Runtime(MockLedger(crypto_params, get_function()))
        runtime_2 = Runtime(MockLedger(crypto_params, get_function()))

        user = runtime_1.new_user_account()
        runtime_2.register_account(user)
        check_user_1 = runtime_1.get_account_for_address(user.address)
        check_user_2 = runtime_2.get_account_for_address(user.address)

        self.assertEqual(check_user_1, user)
        self.assertEqual(check_user_2, user)