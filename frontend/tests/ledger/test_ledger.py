from unittest import TestCase

from zapper_backend import trusted_setup

from tests.assembly.test_assembly import get_simple_function
from zapper.assembly.assembly_class import AssemblyClass
from zapper.assembly.fields import AssemblyField
from zapper.lang.type_address import Address
from zapper.ledger.ledger import Ledger, TxRejectedException
from zapper.ledger.transaction import Transaction


class TestLedger(TestCase):
    def __init__(self, *args, **kwargs):
        crypto_params = trusted_setup(dbg_no_circuit_setup=True)
        self.ledger = Ledger(crypto_params, dbg_no_proof=True)

        assembly_class = AssemblyClass("Class", False)
        assembly_class.add_field(AssemblyField("owner", Address))
        assembly_class.add_function(get_simple_function())
        self.ledger.register_classes([assembly_class])
        super().__init__(*args, **kwargs)

    def test_ledger_verify_success(self):
        root = self.ledger.get_current_root()
        serials = ["1", "2"]
        records = ["0acf", "11ce"]
        unique_seed = "3cf102a"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.ledger.verify_and_execute_transaction(transaction)

    def test_ledger_verify_fails_serials_mutual(self):
        root = self.ledger.get_current_root()
        serials = ["1", "2", "1"]
        records = ["0acf", "11ce"]
        unique_seed = "3cf102a"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.assertRaises(TxRejectedException, self.ledger.verify_and_execute_transaction, transaction)

    def test_ledger_verify_fails_serials_reused(self):
        root = self.ledger.get_current_root()
        serials = ["1", "2"]
        records = ["0acf", "11ce"]
        unique_seed = "3cf102a"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.ledger.verify_and_execute_transaction(transaction)

        root = self.ledger.get_current_root()
        serials = ["1"]
        records = ["fe00"]
        unique_seed = "101010"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.assertRaises(TxRejectedException, self.ledger.verify_and_execute_transaction, transaction)

    def test_ledger_verify_fails_seed_reused(self):
        root = self.ledger.get_current_root()
        serials = ["1", "2"]
        records = ["0acf", "11ce"]
        unique_seed = "3cf102a"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.ledger.verify_and_execute_transaction(transaction)

        root = self.ledger.get_current_root()
        serials = ["3"]
        records = ["fe00"]
        unique_seed = "3cf102a"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.assertRaises(TxRejectedException, self.ledger.verify_and_execute_transaction, transaction)

    def test_ledger_verify_fails_stale_root(self):
        root = self.ledger.get_current_root()
        serials = ["1", "2"]
        records = ["0acf", "11ce"]
        unique_seed = "3cf102a"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.ledger.verify_and_execute_transaction(transaction)

        serials = ["3"]
        records = ["fe00"]
        unique_seed = "101010"

        transaction = Transaction("Class", "f", root, serials, records, None, unique_seed, self.ledger.current_time)
        self.assertRaises(TxRejectedException, self.ledger.verify_and_execute_transaction, transaction)
