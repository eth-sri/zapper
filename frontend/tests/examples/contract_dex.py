from tests.examples.contract_coin import Coin
from zapper.lang.contract import Contract, constructor, has_address

from zapper.lang.types import Uint, Long, Address


@has_address
class DexOffer(Contract):

    creator: Address
    for_amount: Uint
    for_asset: Long
    coin: Coin

    @constructor
    def create(self, shared: Address, coin: Coin, for_amount: Uint, for_asset: Long):
        self.owner = shared
        self.creator = self.me
        self.for_amount = for_amount
        self.for_asset = for_asset
        self.coin = coin
        coin.transfer(self.address)

    def abort(self):
        self.require(self.creator == self.me)
        self.coin.transfer(self.me, sender_is_self=True)
        self.kill()

    def accept(self, other: Coin):
        self.require(other.val == self.for_amount)
        self.require(other.asset_id == self.for_asset)
        self.coin.transfer(self.me, sender_is_self=True)
        other.transfer(self.creator)
        self.kill()
