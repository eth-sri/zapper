from eval.scenarios.coin import Coin
from zapper.lang.contract import Contract, constructor, has_address

from zapper.lang.types import Uint, Long, Address
from zapper.ledger.ledger import Ledger
from zapper.runtime.runtime import Runtime

# META-NAME Exchange
# META-DESC A private decentralized coin exchange.


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


def run_dex(ledger: Ledger):
    runtime = Runtime(ledger)
    user_1 = runtime.new_user_account()
    user_2 = runtime.new_user_account()
    shared = runtime.new_user_account()

    factory = runtime.get_class_handle(Coin)
    coin_1 = factory.mint(1000, sender=user_1)
    coin_2 = factory.mint(300, sender=user_2)
    asset_2 = coin_2.asset_id

    dex = runtime.get_class_handle(DexOffer).create(shared.address, coin_1, 300, asset_2, sender=user_1)

    dex.accept(coin_2, sender=user_2)
