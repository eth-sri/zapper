from typing import List, Optional

from zapper_backend import ExecutionResult

class Transaction:
    def __init__(self, class_name: str, function_name: str, merkle_tree_root: str, consumed_serials: List[str], new_records: List[str], proof: Optional[str], unique_seed: str, current_time: int):
        self.class_name = class_name
        self.function_name = function_name
        self.merkle_tree_root = merkle_tree_root
        self.consumed_serials = consumed_serials
        self.new_records = new_records
        self.proof = proof
        self.unique_seed = unique_seed
        self.current_time = current_time

    @staticmethod
    def from_execution_result(class_name: str, function_name: str, exec_res: ExecutionResult) -> 'Transaction':
        return Transaction(class_name, function_name, exec_res.merkle_tree_root, exec_res.consumed_serials, exec_res.new_records, exec_res.proof, exec_res.unique_seed, int(exec_res.current_time, 16))
