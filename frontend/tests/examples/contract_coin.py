from zapper.lang.contract import Contract, constructor, internal

from zapper.lang.types import Uint, Address, Long


class Coin(Contract):

    val: Uint
    asset_id: Long

    @constructor
    @internal
    def create(self, val: Uint, owner: Address, asset_id: Long):
        self.val = val
        self.owner = owner
        self.asset_id = asset_id

    @constructor
    def mint(self, v: Uint):
        self.val = v
        self.owner = self.me
        self.asset_id = self.fresh()

    def split(self, v: Uint) -> 'Coin':
        self.require(self.owner == self.me)
        self.require(self.val >= v)
        self.val = self.val - v
        return self.create_new_object(Coin.create, v, self.me, self.asset_id)

    def merge(self, other: 'Coin'):
        self.require(self.owner == self.me)
        self.require(other.owner == self.me)
        self.require(self != other)
        other.val = other.val + self.val
        self.kill()

    def transfer(self, recipient: Address):
        self.require(self.owner == self.me)
        self.owner = recipient
