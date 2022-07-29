import unittest
from unittest import TestCase

from tests.examples.contract_coin import Coin
from tests.examples.contract_dex import DexOffer
from tests.examples.contract_example_1 import ContractExample1
from tests.examples.contract_example_2 import ContractExample2
from tests.examples.contract_example_3 import ContractExample3
from tests.examples.contract_example_4 import ContractExample4, InnerExample

from zapper.ledger.ledger import Ledger
from zapper.compiler.compiler import compile_contract

from zapper_backend import trusted_setup, enable_logging as enable_backend_logging

from zapper.runtime.runtime import Runtime, BackendExecuteException


class TestEndToEnd(TestCase):

    def __init__(self, *args, **kwargs):
        # initialize ledger
        crypto_params = trusted_setup(dbg_no_circuit_setup=True)
        self.ledger = Ledger(crypto_params, dbg_no_proof=True)

        # compile and register classes
        classes = [ContractExample1, ContractExample2, ContractExample3, ContractExample4, InnerExample, Coin, DexOffer]
        compiled = [compile_contract(c) for c in classes]
        self.ledger.register_classes(compiled)
        super().__init__(*args, **kwargs)

    def test_end_to_end_1(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        ex1 = runtime.get_class_handle(ContractExample1).create(sender=user)
        self.assertEqual(ex1.uint, 1)
        self.assertEqual(ex1.addr, user.address)
        self.assertEqual(ex1.owner, user.address)

        ex1.equality(sender=user)

        ex1.inequality(0, sender=user)

        ret = ex1.expression(sender=user)
        self.assertEqual(ret, 3)
        self.assertEqual(ex1.uint, 2)

    def test_end_to_end_1_failed_require(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        ex1 = runtime.get_class_handle(ContractExample1).create(sender=user)
        self.assertRaises(BackendExecuteException, ex1.inequality, 5, sender=user)

    def test_end_to_end_2(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        ex2 = runtime.get_class_handle(ContractExample2).create(300, sender=user)
        self.assertEqual(ex2.count, 300)
        self.assertEqual(ex2.addr, user.address)
        self.assertEqual(ex2.owner, user.address)

        ex2.increment(sender=user)
        self.assertEqual(ex2.count, 303)
        self.assertEqual(ex2.addr, user.address)
        self.assertEqual(ex2.owner, user.address)

    def test_end_to_end_3(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        ex3 = runtime.get_class_handle(ContractExample3).create(sender=user)
        self.assertEqual(ex3.x, 1)
        self.assertEqual(ex3.owner, user.address)

        old = ex3.other
        new = runtime.get_class_handle(ContractExample2).create(300, sender=user)
        ex3.swap(new, sender=user)
        self.assertEqual(old.count, 8)
        self.assertEqual(ex3.x, 3)
        self.assertEqual(ex3.owner, user.address)
        self.assertEqual(ex3.other._hdl_object_id, new._hdl_object_id)

    def test_end_to_end_4(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        ex3 = runtime.get_class_handle(ContractExample3).create(sender=user)

        other = ex3.foo(3, sender=user)
        self.assertEqual(ex3.x, 3)
        self.assertEqual(ex3.owner, user.address)
        self.assertEqual(other.count, 5)

        ex3.bar(sender=user)
        self.assertEqual(ex3.x, 6)
        self.assertEqual(other.count, 8)

    def test_end_to_end_5(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        ex4 = runtime.get_class_handle(ContractExample4).create(sender=user)
        self.assertEqual(ex4.t, self.ledger.current_time)
        self.assertEqual(ex4.a, 20392206902184985077609228398922683890834214387716632278800269364043180190443)
        old_w = ex4.w

        ex4.work(3, sender=user)
        self.assertEqual(ex4.x, 5)
        self.assertNotEqual(ex4.w, old_w)

        ex4.work(4, sender=user)
        self.assertEqual(ex4.x, 20)

    def test_end_to_end_coin(self):
        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        coin = runtime.get_class_handle(Coin).mint(1000, sender=user)
        self.assertEqual(coin.val, 1000)
        self.assertEqual(coin.owner, user.address)
        asset = coin.asset_id

        coin_2 = coin.split(400, sender=user)
        self.assertEqual(coin.val, 600)
        self.assertEqual(coin_2.val, 400)
        self.assertEqual(coin_2.owner, user.address)
        self.assertEqual(coin_2.asset_id, asset)

        coin.merge(coin_2, sender=user)
        self.assertEqual(coin_2.val, 1000)

        user_2 = runtime.new_user_account()
        coin_2.transfer(user_2.address, sender=user)
        self.assertEqual(coin_2.owner, user_2.address)

    @unittest.skip("too many instructions for tiny backend")
    def test_end_to_end_dex(self):
        runtime = Runtime(self.ledger)
        user_1 = runtime.new_user_account()
        user_2 = runtime.new_user_account()
        shared = runtime.new_user_account()

        factory = runtime.get_class_handle(Coin)
        coin_1 = factory.mint(1000, sender=user_1)
        coin_2 = factory.mint(300, sender=user_2)
        asset_2 = coin_2.asset_id

        dex = runtime.get_class_handle(DexOffer).create(shared.address, coin_1, 300, asset_2, sender=user_1)
        dex_address = int(runtime.get_raw_state(dex._hdl_object_id).addr_object, 16)
        self.assertEqual(coin_1.owner, dex_address)

        dex.accept(coin_2, sender=user_2)
        self.assertEqual(coin_1.owner, user_2.address)
        self.assertEqual(coin_2.owner, user_1.address)


@unittest.skip("real proof verification is expensive")
class TestEndToEndWithRealProof(TestCase):

    def test_end_to_end_coin_with_real_proof(self):
        # initialize ledger
        crypto_params = trusted_setup()
        self.ledger = Ledger(crypto_params)

        # compile and register classes
        classes = [Coin]
        compiled = [compile_contract(c) for c in classes]
        self.ledger.register_classes(compiled)

        runtime = Runtime(self.ledger)
        user = runtime.new_user_account()

        runtime.get_class_handle(Coin).mint(1000, sender=user)
