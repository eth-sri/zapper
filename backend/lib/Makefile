all:
	cargo build --release

.PHONY: test
test:
	cargo test --release

.PHONY: test-light
test-light:
	cargo test --release --features tiny -- --test-threads=1

.PHONY: test-full
test-full:
	cargo test --release -- --include-ignored

.PHONY: test-with-trace
test-with-trace:
	cargo test --release --features "tiny circuit-trace"

.PHONY: clean
clean:
	cargo clean
