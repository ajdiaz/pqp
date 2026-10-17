.PHONY: all build test clippy fmt clean doc install-systemd

# Where to drop the systemd user unit (override with SYSTEMD_USER_DIR=...).
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user

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

# Install the systemd user unit that keeps `pqp agent` running in the
# background. Enable it afterwards with:
#   systemctl --user enable --now pqp-agent.service
install-systemd:
	install -d $(SYSTEMD_USER_DIR)
	install -m 0644 contrib/systemd/pqp-agent.service $(SYSTEMD_USER_DIR)/pqp-agent.service
	-systemctl --user daemon-reload
	@echo "Installed $(SYSTEMD_USER_DIR)/pqp-agent.service"
	@echo "Enable with: systemctl --user enable --now pqp-agent.service"
	@echo "Remember to point ExecStart at your pqp binary if it is not /usr/bin/pqp."
