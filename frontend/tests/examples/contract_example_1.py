from zapper.lang.contract import Contract, constructor

from zapper.lang.types import Uint, Address


class ContractExample1(Contract):

    uint: Uint
    addr: Address

    @constructor
    def create(self):
        self.uint = 1
        self.addr = self.me
        self.owner = self.me

    def equality(self):
        self.require_equals(self.owner, self.me)

    def inequality(self, z: Uint):
        self.require(self.uint > z)

    def expression(self) -> Uint:
        self.uint = ((self.uint - self.uint) + 1) * 2
        return 3
