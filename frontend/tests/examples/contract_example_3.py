from zapper.lang.types import Uint

from tests.examples.contract_example_2 import ContractExample2
from zapper.lang.contract import Contract, constructor


class ContractExample3(Contract):

    other: ContractExample2
    x: Uint

    @constructor
    def create(self):
        self.other = self.create_new_object(ContractExample2.create, 5)  # on-chain object creation
        self.x = 1
        self.owner = self.me

    def swap(self, new_other: ContractExample2):
        self.other.increment()
        self.other = new_other
        self.x = new_other.helper()

    def bar(self):
        self.foo(2).increment()

    def foo(self, factor: Uint) -> ContractExample2:
        self.x *= factor
        return self.other
