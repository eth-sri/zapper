from zapper.lang.contract import constructor, Contract
from zapper.lang.types import Address, Uint


class ContractExample2(Contract):

    addr: Address
    count: Uint

    @constructor
    def create(self, initial_count: Uint):
        self.addr = self.me
        self.count = initial_count
        self.owner = self.me

    def increment(self):
        self.require_equals(self.owner, self.me)
        self.count += self.helper()  # internal call as expression

    def helper(self) -> Uint:
        return 3
