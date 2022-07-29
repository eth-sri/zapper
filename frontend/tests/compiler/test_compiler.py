from typing import Type
from unittest import TestCase

from tests.examples.contract_example_1 import ContractExample1
from tests.examples.contract_example_2 import ContractExample2
from tests.examples.contract_example_3 import ContractExample3
from tests.examples.contract_example_4 import ContractExample4

from zapper.lang.contract import Contract
from zapper.compiler.compiler import compile_contract


contract_example_1_assembly_str = """
class tests.examples.contract_example_1.ContractExample1:
    address addr
    uint uint
    address owner

    def create() -> tests.examples.contract_example_1.ContractExample1 return:
        NEW self tests.examples.contract_example_1.ContractExample1 _
        MOV constant#1 1 _
        STORE constant#1 self uint
        STORE me self addr
        STORE me self owner
        MOV return self _

    def equality(tests.examples.contract_example_1.ContractExample1 self) -> uint return:
        LOAD owner#1 self owner
        BinaryOperator.EQUALS EQUALS#2 owner#1 me
        REQ _ EQUALS#2 _
        MOV return 0 _

    def expression(tests.examples.contract_example_1.ContractExample1 self) -> uint return:
        LOAD read#1 self uint
        LOAD read#2 self uint
        BinaryOperator.MINUS MINUS#3 read#1 read#2
        BinaryOperator.PLUS PLUS#4 MINUS#3 1
        BinaryOperator.MULTIPLY MULTIPLY#5 PLUS#4 2
        STORE MULTIPLY#5 self uint
        MOV return 3 _

    def inequality(tests.examples.contract_example_1.ContractExample1 self, uint z) -> uint return:
        LOAD read#1 self uint
        BinaryOperator.LESS LESS#2 z read#1
        REQ _ LESS#2 _
        MOV return 0 _
""".strip()


contract_example_2_assembly_str = """
class tests.examples.contract_example_2.ContractExample2:
    address addr
    uint count
    address owner

    def create(uint initial_count) -> tests.examples.contract_example_2.ContractExample2 return:
        NEW self tests.examples.contract_example_2.ContractExample2 _
        STORE me self addr
        STORE initial_count self count
        STORE me self owner
        MOV return self _

    def helper(tests.examples.contract_example_2.ContractExample2 self) -> uint return:
        MOV return 3 _

    def increment(tests.examples.contract_example_2.ContractExample2 self) -> uint return:
        LOAD owner#1 self owner
        BinaryOperator.EQUALS EQUALS#2 owner#1 me
        REQ _ EQUALS#2 _
        LOAD read#3 self count
        CALL tests.examples.contract_example_2.ContractExample2.helper return#4 self
        BinaryOperator.PLUS PLUS#5 read#3 return#4
        STORE PLUS#5 self count
        MOV return 0 _
""".strip()


contract_example_3_assembly_str = """
class tests.examples.contract_example_3.ContractExample3:
    tests.examples.contract_example_2.ContractExample2 other
    uint x
    address owner

    def bar(tests.examples.contract_example_3.ContractExample3 self) -> uint return:
        CALL tests.examples.contract_example_3.ContractExample3.foo return#1 self 2
        CALL tests.examples.contract_example_2.ContractExample2.increment return#2 return#1
        MOV return 0 _

    def create() -> tests.examples.contract_example_3.ContractExample3 return:
        NEW self tests.examples.contract_example_3.ContractExample3 _
        CALL tests.examples.contract_example_2.ContractExample2.create return#1 5
        STORE return#1 self other
        MOV constant#2 1 _
        STORE constant#2 self x
        STORE me self owner
        MOV return self _

    def foo(tests.examples.contract_example_3.ContractExample3 self, uint factor) -> tests.examples.contract_example_2.ContractExample2 return:
        LOAD read#1 self x
        BinaryOperator.MULTIPLY MULTIPLY#2 read#1 factor
        STORE MULTIPLY#2 self x
        LOAD read#3 self other
        MOV return read#3 _

    def swap(tests.examples.contract_example_3.ContractExample3 self, tests.examples.contract_example_2.ContractExample2 new_other) -> uint return:
        LOAD read#1 self other
        CALL tests.examples.contract_example_2.ContractExample2.increment return#2 read#1
        STORE new_other self other
        CALL tests.examples.contract_example_2.ContractExample2.helper return#3 new_other
        STORE return#3 self x
        MOV return 0 _
""".strip()


contract_example_4_assembly_str = """
class tests.examples.contract_example_4.ContractExample4:
    address a
    uint t
    long w
    uint x
    address owner

    def create() -> tests.examples.contract_example_4.ContractExample4 return:
        NEW self tests.examples.contract_example_4.ContractExample4 _
        MOV constant#1 100 _
        STORE constant#1 self x
        MOV constant#2 20392206902184985077609228398922683890834214387716632278800269364043180190443 _
        STORE constant#2 self a
        FRESH fresh#3 _ _
        STORE fresh#3 self w
        STORE me self owner
        NOW now#4 _ _
        STORE now#4 self t
        MOV return self _

    def work(tests.examples.contract_example_4.ContractExample4 self, uint z) -> tests.examples.contract_example_4.InnerExample return:
        FRESH fresh#1 _ _
        STORE fresh#1 self w
        BinaryOperator.LESS LESS#2 3 z
        LOAD read#3 self x
        BinaryOperator.MULTIPLY MULTIPLY#4 read#3 z
        MOV res#5 5 _
        CMOV res#5 LESS#2 MULTIPLY#4
        STORE res#5 self x
        CALL tests.examples.contract_example_4.InnerExample.create return#6
        MOV return return#6 _
""".strip()


class Wrapper:
    class TestCompiler(TestCase):

        def __init__(self, contract: Type[Contract], expected: str, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.contract = contract
            self.expected = expected

        def test_compile(self):
            assembly_class = compile_contract(self.contract)
            assembly_class_str = str(assembly_class)
            if assembly_class_str != self.expected:
                print(assembly_class_str)
                self.assertEqual(assembly_class_str, self.expected)


class TestContractExample1(Wrapper.TestCompiler):

    def __init__(self, *args, **kwargs):
        super().__init__(ContractExample1, contract_example_1_assembly_str, *args, **kwargs)


class TestContractExample2(Wrapper.TestCompiler):

    def __init__(self, *args, **kwargs):
        super().__init__(ContractExample2, contract_example_2_assembly_str, *args, **kwargs)


class TestContractExample3(Wrapper.TestCompiler):

    def __init__(self, *args, **kwargs):
        super().__init__(ContractExample3, contract_example_3_assembly_str, *args, **kwargs)


class TestContractExample4(Wrapper.TestCompiler):

    def __init__(self, *args, **kwargs):
        super().__init__(ContractExample4, contract_example_4_assembly_str, *args, **kwargs)
