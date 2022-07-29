from eval.scenarios.coin import Coin
from zapper.lang.contract import Contract, constructor, only
from zapper.lang.type_address import Address
from zapper.lang.types import Uint, Long, AddressConst, LongConst
from zapper.ledger.ledger import Ledger
from zapper.runtime.runtime import Runtime, Account

# to be set _after_ parameter generation, but before compilation
TICKET_AUTHORITY_ACCOUNT: Account = None
TICKET_ASSET_ID: Long = None

# META-NAME Tickets
# META-DESC A public transport ticketing system with untraceable multi-journey tickets.


class TicketProof(Contract):

    ticket_holder: Address
    last_stamped: Uint

    @only("eval.scenarios.train_ticket.Ticket")
    @constructor
    def create(self, ticket_holder: Address, last_stamped: Uint):
        self.ticket_holder = ticket_holder
        self.last_stamped = last_stamped
        self.owner = AddressConst(TICKET_AUTHORITY_ACCOUNT.address)


class Ticket(Contract):

    charges: Uint
    last_stamped: Uint

    @constructor
    def create(self, payment: Coin):
        self.require(payment.val == 50)     # price for 10 journeys
        self.require(payment.asset_id == LongConst(TICKET_ASSET_ID))
        payment.transfer(AddressConst(TICKET_AUTHORITY_ACCOUNT.address))    # pay to ticket authority
        self.owner = self.me
        self.charges = 10
        self.last_stamped = 0

    def stamp(self):
        self.require(self.charges > 0)
        self.charges -= 1
        self.last_stamped = self.now()

    def prove_stamped(self) -> TicketProof:
        self.require(self.last_stamped + 2 >= self.now())
        return self.create_new_object(TicketProof.create, self.owner, self.last_stamped)

    def transfer(self, new_holder: Address):
        self.require(self.last_stamped + 2 < self.now())
        self.owner = new_holder


def run_ticket(coin_large: 'ObjectHandle', user_1: Account):
    runtime = coin_large._hdl_runtime
    runtime.sync()
    user_2 = runtime.new_user_account()

    # use hardcoded ticket authority
    ticket_authority = TICKET_AUTHORITY_ACCOUNT
    runtime.register_account(ticket_authority)

    coin = coin_large.split(50, sender=user_1)

    ticket = runtime.get_class_handle(Ticket).create(coin, sender=user_1)
    ticket.transfer(user_2.address, sender=user_1)
    ticket.stamp(sender=user_2)
    proof = ticket.prove_stamped(sender=user_2)

    assert(coin.owner == ticket_authority.address)
    assert(proof.owner == ticket_authority.address)
    assert(proof.ticket_holder == user_2.address)
