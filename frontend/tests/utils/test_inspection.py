import unittest
from unittest import TestCase

from zapper.utils.inspection import extract_argument_from_stack, get_class_that_defined_method, \
    get_qualified_name, get_member_names_no_superclass

class SuperClass:
    z: int

    def h(self):
        pass


class ClassWithAttributes(SuperClass):

    x: int
    y: str


class ClassWithFunctions(SuperClass):

    def f(self):
        pass

    def g(self):
        pass


class TestInspection(TestCase):

    def test_get_member_names_attributes(self):
        names = get_member_names_no_superclass(ClassWithAttributes, include_fields=True, include_functions=False)
        self.assertEqual(sorted(names), ['x', 'y'])

    def test_get_member_names_functions(self):
        names = get_member_names_no_superclass(ClassWithFunctions, include_fields=False, include_functions=True)
        self.assertEqual(sorted(names), ['f', 'g'])

    def test_extract_argument_from_stack(self):
        receiver = extract_argument_from_stack(0, 0, expected_type=TestInspection)
        self.assertIs(self, receiver)

    @unittest.skip("Pending fix on stackoverflow")
    def test_get_class_that_defined_method(self):
        cls = get_class_that_defined_method(ClassWithFunctions.f)
        self.assertIs(cls, ClassWithFunctions)

    def test_get_qualified_name(self):
        qualified_name = get_qualified_name(ClassWithFunctions)
        self.assertIn('test_inspection.ClassWithFunctions', qualified_name)
