from zapper.lang.type_address import Address
from zapper.lang.types import Uint, Long, AddressConst

from zapper.lang.contract import Contract, constructor, only


class InnerExample(Contract):

    x: Uint

    @only("tests.examples.contract_example_4.ContractExample4")
    @constructor
    def create(self):
        self.x = 0
        self.owner = self.me


class ContractExample4(Contract):

    x: Uint
    w: Long
    t: Uint
    a: Address

    @constructor
    def create(self):
        self.x = 100
        self.a = AddressConst(20392206902184985077609228398922683890834214387716632278800269364043180190443)
        self.w = self.fresh()
        self.owner = self.me
        self.t = self.now()

    def work(self, z: Uint) -> InnerExample:
        self.w = self.fresh()
        self.x = self.if_then_else(z > 3, self.x * z, 5)
        return self.create_new_object(InnerExample.create)
