from eval.scenarios.coin import Coin
from zapper.lang.contract import Contract, constructor, only, has_address
from zapper.lang.type_address import Address
from zapper.lang.types import Uint
from zapper.ledger.ledger import Ledger
from zapper.runtime.runtime import Runtime

# META-NAME Heritage
# META-DESC A heritable coin wallet with anonymous heirs and private shares.


class Share(Contract):

    heir: Address
    wallet: Address
    nof_parts: Uint

    @only("eval.scenarios.heritable_wallet.Wallet")
    @constructor
    def create(self, wallet: Address, heir: Address, shared: Address, nof_parts: Uint):
        self.wallet = wallet
        self.nof_parts = nof_parts
        self.heir = heir
        self.owner = shared

    def invalidate(self):
        self.require(self.wallet == self.me)
        self.kill()


@has_address
class Wallet(Contract):

    proprietor: Address
    wallet: Coin
    remaining_parts: Uint
    total_parts: Uint
    last_heartbeat: Uint

    @constructor
    def create(self, shared: Address, wallet: Coin, total_parts: Uint):
        self.require(total_parts > 0)
        self.owner = shared
        self.proprietor = self.me
        self.wallet = wallet
        wallet.transfer(self.address)
        self.remaining_parts = total_parts
        self.total_parts = total_parts
        self.last_heartbeat = self.now()

    def beat(self):
        self.require(self.proprietor == self.me)
        self.last_heartbeat = self.now()

    def add_heir(self, heir: Address, shared: Address, nof_parts: Uint) -> Share:
        self.beat()
        self.require(self.proprietor == self.me)
        self.require(self.remaining_parts >= nof_parts)
        self.remaining_parts -= nof_parts
        return self.create_new_object(Share.create, self.address, heir, shared, nof_parts)

    def remove_heir(self, heir_parts: Share):
        self.beat()
        self.require(self.proprietor == self.me)
        self.remaining_parts += heir_parts.nof_parts
        heir_parts.invalidate(sender_is_self=True)

    def pay_in(self, coin: Coin):
        self.beat()
        self.require(self.proprietor == self.me)
        coin.merge(self.wallet, sender_is_self=True)

    def pay_out(self, val: Uint) -> Coin:
        self.beat()
        self.require(self.proprietor == self.me)
        coin = self.wallet.split(val, sender_is_self=True)
        coin.transfer(self.proprietor, sender_is_self=True)
        return coin

    def claim(self, one_part_val: Uint, heir_parts: Share) -> Coin:
        self.require(self.last_heartbeat + 30 < self.now())
        self.require(heir_parts.heir == self.me)
        self.require(heir_parts.wallet == self.address)
        self.require(one_part_val*self.total_parts <= self.wallet.val)    # floor division
        coin = self.wallet.split(one_part_val*heir_parts.nof_parts, sender_is_self=True)
        coin.transfer(heir_parts.heir, sender_is_self=True)
        heir_parts.invalidate(sender_is_self=True)
        return coin


def run_heritable(ledger: Ledger):
    runtime = Runtime(ledger)
    user = runtime.new_user_account()
    shared = runtime.new_user_account()
    heir_1 = runtime.new_user_account()
    heir_2 = runtime.new_user_account()
    shared_1 = runtime.new_user_account()
    shared_2 = runtime.new_user_account()

    factory = runtime.get_class_handle(Coin)
    coin_1 = factory.mint(280, sender=user)
    coin_2 = coin_1.split(30, sender=user)

    wallet = runtime.get_class_handle(Wallet).create(shared.address, coin_1, 100, sender=user)
    part_1 = wallet.add_heir(heir_1.address, shared_1.address, 60, sender=user)
    part_2 = wallet.add_heir(heir_2.address, shared_2.address, 30, sender=user)
    wallet.remove_heir(part_2, sender=user)
    coin_2.transfer(wallet.address, sender=user)
    coin_3 = wallet.pay_out(80, sender=user)
    wallet.pay_in(coin_2, sender=user)

    ledger.test_increase_current_time_by(31)
    coin_4 = wallet.claim(2, part_1, sender=heir_1)

    assert(coin_4.owner == heir_1.address)
    assert(coin_4.val == 120)
    assert(coin_3.owner == user.address)
    assert(coin_3.val == 80)
    assert(wallet.remaining_parts == 40)
    assert(wallet.wallet.val == 80)
