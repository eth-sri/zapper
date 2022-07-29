from zapper.lang.contract import Contract, constructor, internal
from zapper.lang.types import Uint, Long, Address
from zapper.ledger.ledger import Ledger

from zapper.runtime.runtime import Runtime

# META-NAME Coin
# META-DESC A private untraceable coin.

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


def run_coin(ledger: Ledger):
    runtime = Runtime(ledger)
    user = runtime.new_user_account()

    coin = runtime.get_class_handle(Coin).mint(1000, sender=user)

    coin_2 = coin.split(400, sender=user)

    coin.merge(coin_2, sender=user)

    user_2 = runtime.new_user_account()
    coin_2.transfer(user_2.address, sender=user)

    return coin_2, user_2