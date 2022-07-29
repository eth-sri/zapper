from unittest import TestCase

from zapper.lang.types import Uint

from tests.examples.contract_example_2 import ContractExample2
from tests.lang.debug_event_observer import DebugEventObserver
from tests.examples.contract_example_1 import ContractExample1
from tests.examples.contract_example_3 import ContractExample3


class TestContract(TestCase):

    def test_contract_get_fields(self):
        field_names = list(ContractExample1.zapper_fields.keys())
        self.assertEqual(field_names, ["addr", "uint", "owner"])

    def test_contract_get_functions(self):
        function_names = list(ContractExample1.zapper_functions.keys())
        self.assertEqual(function_names, ['create', 'equality', 'expression', 'inequality'])

    def test_contract_get_arguments(self):
        constructor_arguments = ContractExample1.zapper_functions['create'].argument_types
        self.assertEqual(constructor_arguments, {'self': ContractExample1})

        equality_arguments = ContractExample1.zapper_functions['equality'].argument_types
        self.assertEqual(equality_arguments, {'self': ContractExample1})

        inequality_arguments = ContractExample1.zapper_functions['inequality'].argument_types
        self.assertEqual(inequality_arguments, {'self': ContractExample1, 'z': Uint})

    def test_contract_get_arguments_reference(self):
        swap_arguments = ContractExample3.zapper_functions['swap'].argument_types
        self.assertEqual(swap_arguments, {'self': ContractExample3, 'new_other': ContractExample2})

    def test_event_callback_write(self):
        o = DebugEventObserver(ContractExample1)
        ContractExample1.create(o)
        self.assertEqual(o.ops, ['write uint', 'me', 'write addr', 'me', 'write owner'])

    def test_event_callback_call(self):
        o = DebugEventObserver(ContractExample2)
        ContractExample2.increment(o)
        self.assertEqual(o.ops, ['owner', 'me', 'require_equals', 'read count', 'call helper', 'write count'])

    def test_event_callback_create(self):
        o = DebugEventObserver(ContractExample3)
        ContractExample3.create(o)
        self.assertEqual(o.ops, ['new ContractExample2', 'write other', 'write x', 'me', 'write owner'])
