from clvm_rs import Program


def load_clvm(path, mod=None):
    with open(f"chiaswap/{path}.hex") as f:
        t = f.read().strip()
        return Program.from_bytes(bytes.fromhex(t))
