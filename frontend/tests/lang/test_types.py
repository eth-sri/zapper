from collections import OrderedDict
from unittest import TestCase

from zapper.lang.types import Uint

from tests.examples.contract_example_1 import ContractExample1
from zapper.lang.function import extract_types


class TestContract(TestCase):

    def test_extract_types_1(self):
        types, return_type = extract_types(ContractExample1, ContractExample1.create)
        self.assert_equal_dict_ordered(types, {'self': ContractExample1})
        self.assertEqual(return_type, Uint)

    def test_extract_types_2(self):
        types, return_type = extract_types(ContractExample1, ContractExample1.inequality)
        self.assert_equal_dict_ordered(types, {'self': ContractExample1, 'z': Uint})
        self.assertEqual(return_type, Uint)

    def assert_equal_dict_ordered(self, d1, d2):
        d1 = OrderedDict(d1.items())
        d2 = OrderedDict(d2.items())

        self.assertEqual(d1, d2)
