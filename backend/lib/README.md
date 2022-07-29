# Zapper Backend Library

## Build

### For development
```bash
make test
```

### For fast performance
On modern CPUs, can rely on specialized instructions:
```bash
export RUSTFLAGS="-C target-feature=+bmi2,+adx"
cargo run --release
```
Adding `--emit asm` to the `RUSTFLAGS` above may or may not help, depending on the machine.
For CPUs not supporting these instructions, remove `features = ["asm"]` for `ark-ff` in `Cargo.toml`.
