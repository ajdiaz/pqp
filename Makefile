.PHONY: all build test clippy fmt clean doc

all: build test clippy fmt

build:
	cargo build --release

debug:
	cargo build

test:
	cargo test -- --test-threads=1

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --check

clean:
	cargo clean

doc:
	cargo doc --no-deps
