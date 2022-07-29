import eval.scenarios.train_ticket
from eval.scenarios.auction import Auction, run_auction
from eval.scenarios.coin import Coin, run_coin
from eval.scenarios.dex_offer import DexOffer, run_dex
from eval.scenarios.heritable_wallet import Wallet, Share, run_heritable
from eval.scenarios.reviews import Review, Result, Paper, run_reviews
from eval.scenarios.train_ticket import run_ticket, Ticket, TicketProof
from eval.scenarios.working_hours import run_working_hours, WorkLog, Aggregated
from zapper.runtime.runtime import Account
from zapper.utils.data_logging import time_measure, data_context
from zapper.ledger.ledger import Ledger
from zapper.zapper_logging import getLogger
from zapper.compiler.compiler import compile_contract
from zapper_backend import trusted_setup, new_user_account


def compile_app(ledger, classes):
    with time_measure("compile"):
        compiled = [compile_contract(c) for c in classes]
        ledger.register_classes(compiled)


if __name__ == "__main__":
    log = getLogger(__name__)
    log.info("starting evaluation...")

    try:
        log.info("performing trusted setup...")
        with time_measure("setup"):
            # change the following flags for faster debugging
            crypto_params = trusted_setup(dbg_no_circuit_setup=False)
            ledger = Ledger(crypto_params, dbg_no_proof=False)

        log.info("running scenarios...")
        with data_context("coin"):
            compile_app(ledger, [Coin])
            coin, user = run_coin(ledger)

        with data_context("dex"):
            compile_app(ledger, [DexOffer])
            run_dex(ledger)

        with data_context("auction"):
            compile_app(ledger, [Auction])
            run_auction(ledger)

        with data_context("reviews"):
            compile_app(ledger, [Review, Result, Paper])
            run_reviews(ledger)

        with data_context("heritable"):
            compile_app(ledger, [Wallet, Share])
            run_heritable(ledger)

        with data_context("working-hours"):
            eval.scenarios.working_hours.EMPLOYER_ACCOUNT = Account(new_user_account(crypto_params))
            compile_app(ledger, [WorkLog, Aggregated])
            run_working_hours(ledger)

        with data_context("ticket"):
            eval.scenarios.train_ticket.TICKET_AUTHORITY_ACCOUNT = Account(new_user_account(crypto_params))
            eval.scenarios.train_ticket.TICKET_ASSET_ID = coin.asset_id
            compile_app(ledger, [Ticket, TicketProof])
            run_ticket(coin, user)

    except BaseException as e:
        log.error("experiments aborted with error: %s", str(e), exc_info=1)
        exit(1)

    log.info("finished evaluation...")
