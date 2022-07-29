from typing import List, Dict

from zapper.lang.contract import Contract
from zapper.lang.types import Uint, Address, Long
from zapper.ledger.ledger import Ledger

from zapper_backend import Runtime as BackendRuntime, ObjectState
from zapper_backend import KeyPair

from zapper.ledger.transaction import Transaction
from zapper.runtime.handles import ClassHandle
from zapper.utils.data_logging import data_context, time_measure
from zapper.utils.general import to_hex_str
from zapper.zapper_logging import getLogger


logger = getLogger(__name__)


class BackendExecuteException(Exception):
    pass


class Account:
    def __init__(self, keys: KeyPair):
        self.keys = keys
        self.address = Address(int(keys.address, 16))

    def __eq__(self, other):
        return self.keys.address == other.keys.address and self.keys.secret_key == other.keys.secret_key \
               and self.keys.public_key == other.keys.public_key and self.address == other.address


class Runtime:
    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.backend = BackendRuntime(ledger.crypto_params)
        self.sync()

    def sync(self):
        # synchronize backend with ledger
        logger.info("synchronizing local state with ledger...")
        synced = self.backend.get_nof_synced_tx()
        for i in range(synced, len(self.ledger.accepted_transactions)):
            self.backend.sync_tx(i, self.ledger.accepted_transactions[i][0], self.ledger.accepted_transactions[i][1])

    def new_user_account(self) -> Account:
        account = Account(self.backend.new_user_account())
        logger.info("created new user with address 0x%x", account.address)
        return account

    def register_account(self, account: Account):
        self.backend.register_account(account.keys)
        logger.info("registered account with address 0x%x", account.address)

    def get_account_for_address(self, address: Address) -> Account:
        account = self.backend.get_account_for_address(to_hex_str(address))
        return Account(account)

    def get_class_handle(self, clazz: Contract):
        return ClassHandle(self, clazz)

    def call_function(self, class_name: str, function_name: str, sender_account: Account, arguments: List[Uint | Long | Address]) -> int:
        with data_context(class_name):
            with data_context(function_name):
                # get serialized instructions for called function
                processor_function = self.ledger.get_serialized_function(class_name, function_name)

                # prepare arguments in the order [me, arg(0), arg(1), ...], in hex string format
                processor_arguments = Runtime.prepare_arguments(sender_account, arguments)

                # use backend to execute instructions and get transaction data
                logger.info("locally executing %s.%s with arguments %s...", class_name, function_name, str(processor_arguments))
                try:
                    with time_measure("execute"):
                        res = self.backend.execute(to_hex_str(processor_function.class_id),
                                                   to_hex_str(processor_function.function_id),
                                                   processor_function.instructions,
                                                   processor_arguments,
                                                   processor_function.return_register,
                                                   to_hex_str(self.ledger.current_time))
                except BaseException as e:
                    logger.error(f"error while executing instructions: {str(e)}")
                    raise BackendExecuteException(e)
                logger.info(f"finished execution with return value 0x{res.return_value}")

                # send transaction to ledger
                transaction = Transaction.from_execution_result(class_name, function_name, res)
                logger.info("sending transaction to ledger for verification...")
                with time_measure("verify"):
                    self.ledger.verify_and_execute_transaction(transaction)
                logger.info("successfully accepted transaction at ledger")

                # sync backend
                logger.info("synchronizing local state with new data...")
                self.backend.sync_tx(self.backend.get_nof_synced_tx(), transaction.consumed_serials, transaction.new_records)

                logger.info("finished call to %s.%s", class_name, function_name)

                return int(res.return_value, 16)

    def get_raw_state(self, object_id: int) -> ObjectState:
        return self.backend.get_state(to_hex_str(object_id))

    def get_field_values(self, object_id: int) -> Dict[str, Uint | Long | Address]:
        field_values = {}
        obj_state = self.get_raw_state(object_id)
        assembly_class = self.ledger.get_class_for_id(int(obj_state.contract_id, 16))
        for f in assembly_class.fields.values():
            val = obj_state.addr_owner if f.location == 0 else obj_state.payload[f.location - 1]
            field_values[f.field_name] = int(val, 16)
        return field_values

    @staticmethod
    def prepare_arguments(sender_account: Account, arguments: List[Uint | Long | Address]) -> List[str]:
        return [to_hex_str(sender_account.address)] + [to_hex_str(a) for a in arguments]
