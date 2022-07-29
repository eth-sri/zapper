from eval.scenarios.coin import Coin
from zapper.lang.contract import Contract, constructor, has_address
from zapper.lang.type_address import Address
from zapper.lang.types import Uint, Long
from zapper.ledger.ledger import Ledger
from zapper.runtime.runtime import Runtime

# META-NAME Auction
# META-DESC A private decentralized coin auction.


@has_address
class Auction(Contract):

    initiator: Address
    end_time: Uint
    for_asset: Long
    offered_coin: Coin
    highest_bid: Uint
    highest_address: Address
    highest_bid_coin: Coin

    @constructor
    def create(self, shared: Address, offered_coin: Coin, for_asset: Long, start_bid: Uint, end_time: Uint):
        self.owner = shared
        self.initiator = self.me
        self.end_time = end_time
        self.for_asset = for_asset
        self.offered_coin = offered_coin
        self.highest_bid = start_bid
        self.highest_address = self.me
        self.highest_bid_coin = self.create_new_object(Coin.mint, 0)
        self.highest_bid_coin.transfer(self.address)
        offered_coin.transfer(self.address)

    def bid(self, coin: Coin):
        self.require(self.end_time >= self.now())
        self.require(coin.val > self.highest_bid)
        self.require(coin.asset_id == self.for_asset)
        self.highest_bid_coin.transfer(self.highest_address, sender_is_self=True)    # pay bid back to previous highest bitter
        self.highest_bid_coin = coin
        self.highest_bid = coin.val
        self.highest_address = self.me
        coin.transfer(self.address)

    def won(self):
        self.require(self.end_time < self.now())
        self.require(self.highest_address == self.me)
        self.offered_coin.transfer(self.me, sender_is_self=True)
        self.highest_bid_coin.transfer(self.initiator, sender_is_self=True)
        self.kill()


def run_auction(ledger: Ledger):
    runtime = Runtime(ledger)
    user_1 = runtime.new_user_account()
    user_2 = runtime.new_user_account()
    shared = runtime.new_user_account()
    end_time = ledger.current_time + 10

    factory = runtime.get_class_handle(Coin)
    coin_1 = factory.mint(20, sender=user_1)
    coin_2 = factory.mint(300, sender=user_2)
    coin_3 = coin_2.split(100, sender=user_2)
    asset_2 = coin_2.asset_id

    auction = runtime.get_class_handle(Auction).create(shared.address, coin_1, asset_2, 10, end_time, sender=user_1)
    auction.bid(coin_3, sender=user_2)
    auction.bid(coin_2, sender=user_2)

    ledger.test_increase_current_time_by(15)
    auction.won(sender=user_2)

    assert(coin_2.owner == user_1.address)
    assert(coin_1.owner == user_2.address)
    assert(coin_3.owner == user_2.address)
