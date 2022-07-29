from typing import List, Set, Dict, Tuple

from zapper.assembly.assembly_class import AssemblyClass
from zapper.assembly.assembly_storage import AssemblyStorage
from zapper.ledger.transaction import Transaction

from zapper_backend import MerkleTree, CryptoParameters, Verifier

from zapper.runtime.serialized_assembly import SerializedFunction
from zapper.utils.data_logging import data_context, write_data, time_measure
from zapper.utils.general import to_hex_str


class TxRejectedException(Exception):
    pass


def add_to_set_check_unique(s: set, elem) -> bool:
    if elem in s:
        return False
    s.add(elem)
    return True


class Ledger:
    def __init__(self, params: CryptoParameters, dbg_no_proof=False):
        self.assembly_storage = AssemblyStorage()
        self.serialized_functions: Dict[('str', 'str'), SerializedFunction] = {}
        self.published_serial_numbers: Set[str] = set()
        self.published_unique_seeds: Set[str] = set()
        self.merkle_tree = MerkleTree(params)
        self.crypto_params = params
        self.next_record_idx = 0
        self.accepted_transactions: List[Tuple[List[str], List[str]]] = []
        self.current_time = 5555    # some test value
        if dbg_no_proof:
            self.verifier = None
        else:
            self.verifier = Verifier(params)

    def register_classes(self, classes: List[AssemblyClass]):
        for c in classes:
            self.assembly_storage.add_class(c)
        self.assembly_storage.link_new_classes()
        self.assembly_storage.check_new_classes()
        self.assembly_storage.inline_new_classes()
        self.assembly_storage.insert_runtime_checks_for_new_classes()
        self.assembly_storage.allocation_for_new_classes()
        self.assembly_storage.reset_new_classes()

        # serialize all public functions
        for c in classes:
            with data_context(c.qualified_name):
                function_id = 0
                for f in c.functions.values():
                    with data_context(f.function_name):
                        write_data({"nof_instructions": len(f.get_all_instructions())})
                    if not f.is_private:
                        self.serialized_functions[(c.qualified_name, f.function_name)] = SerializedFunction(c.class_id, function_id, f)
                        function_id += 1

    def get_class_for_id(self, class_id: int) -> AssemblyClass:
        for c in self.assembly_storage.assembly_classes.values():
            if class_id == c.class_id:
                return c
        raise ValueError(f"unknown class id {class_id}")

    def get_serialized_function(self, class_name: str, function_name: str) -> SerializedFunction:
        if (class_name, function_name) not in self.serialized_functions:
            raise ValueError(f"unknown function {class_name}.{function_name} or function not public")
        return self.serialized_functions[(class_name, function_name)]

    def get_current_root(self) -> str:
        return self.merkle_tree.get_root()

    def test_increase_current_time_by(self, amount: int):
        """
        Currently, for testing purposes, the timestamping mechanism is manually driven by the user.
        """
        self.current_time += amount

    def verify_and_execute_transaction(self, transaction: Transaction):
        # check serials of transaction are mutually distinct
        transaction_serials = set()
        for serial in transaction.consumed_serials:
            if not add_to_set_check_unique(transaction_serials, serial):
                raise TxRejectedException("serial numbers of transaction not unique")

        # check serials distinct from all previously seen serials
        if len(transaction_serials.intersection(self.published_serial_numbers)) != 0:
            raise TxRejectedException("at least one serial number of transaction has been observed earlier")

        # check unique_seed is distinct from all previously seen seeds
        if transaction.unique_seed in self.published_unique_seeds:
            raise TxRejectedException("unique_seed has been observed earlier")

        # check merkle root matches current root
        if transaction.merkle_tree_root != self.merkle_tree.get_root():
            raise TxRejectedException("transaction root does not match current merkle tree root")

        # check if timestamp valid
        if transaction.current_time != self.current_time:
            raise TxRejectedException("timestamp of transaction invalid")

        # get serialized function
        serialized_function = self.get_serialized_function(transaction.class_name, transaction.function_name)

        if self.verifier is not None:
            with time_measure("verify_check_proof"):
                try:
                    res = self.verifier.verify(transaction.unique_seed,
                                               transaction.merkle_tree_root,
                                               transaction.consumed_serials,
                                               transaction.new_records,
                                               to_hex_str(serialized_function.class_id),
                                               to_hex_str(serialized_function.function_id),
                                               serialized_function.instructions,
                                               to_hex_str(self.current_time),
                                               transaction.proof)
                except BaseException as e:
                    raise TxRejectedException(f"proof verification raised an error: {str(e)}")
                if not res:
                    raise TxRejectedException("proof verification failed")

        # perform actual state update
        self.published_serial_numbers = self.published_serial_numbers.union(transaction_serials)
        self.published_unique_seeds.add(transaction.unique_seed)
        with time_measure("verify_insert_merkle"):
            for r in transaction.new_records:
                self.merkle_tree.insert(self.next_record_idx, r)
                self.next_record_idx += 1
        self.accepted_transactions.append((list(transaction_serials), transaction.new_records))
