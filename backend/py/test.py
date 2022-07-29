import zapper_backend

def to_hex_str(x: int) -> str:
    s = hex(x)[2:]
    if len(s) % 2 != 0:
        # pad with leading zero to ensure even length
        s = "0" + s
    return s


class Instruction:
    def __init__(self, opcode: int, dst: int, src_1: int, src_1_is_const: bool, src_2: int, src_2_is_const: bool):
        self.opcode = opcode
        self.dst = dst
        self.src_1 = to_hex_str(src_1)
        self.src_1_is_const = src_1_is_const
        self.src_2 = to_hex_str(src_2)
        self.src_2_is_const = src_2_is_const

if __name__ == "__main__":
    zapper_backend.enable_logging()
    crypto_params = zapper_backend.trusted_setup(dbg_no_circuit_setup=True)
    runtime = zapper_backend.Runtime(crypto_params)
    alice = runtime.new_user_account()

    program = [
        Instruction(8, 2, 7, True, 0, False),  # NEW 2 Const(7) _
        Instruction(5, 0, 2, False, 0, True),   # STORE 0 Reg(2) Const(0)  // this.owner = ..
        Instruction(1, 3, 15, True, 0, False),   # MOV 3 Const(15) _
        Instruction(5, 3, 2, False, 3, True),  # STORE 3 Reg(2) Const(3)
        Instruction(1, 0, 2, False, 0, False),   # MOV 0 Reg(2) _           // set return value
    ]
    res = runtime.execute("0222", "0333", program, [alice.address], 0, "9909", dbg_sync_immediately=True)
    oid = res.return_value
    state = runtime.get_state(oid)
    print(state)

    program = [
        Instruction(4, 3, 2, False, 3, True),  # LOAD 3 Reg(2) Const(3)
        Instruction(12, 3, 3, False, 1, True),  # ADD 3 Reg(3) Const(1)
        Instruction(5, 3, 2, False, 4, True),  # STORE 3 Reg(2) Const(4)
    ]
    res = runtime.execute("0222", "0333", program, [alice.address, "00", oid], 0, "9909", dbg_sync_immediately=True)
    state = runtime.get_state(oid)
    print(state)

    merkle_tree = zapper_backend.MerkleTree(crypto_params)
    print(merkle_tree.get_root())
    for record in res.new_records:
        merkle_tree.insert(0, record)
        print(merkle_tree.get_root())
