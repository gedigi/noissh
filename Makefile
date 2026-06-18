# noissh — build & install
#
#   make build         release build
#   make test          run the workspace test suite
#   make check         fmt check + clippy (-D warnings) + tests
#   make install       install to PREFIX/bin (default /usr/local)
#   make uninstall     remove installed binaries
#
# Override the install prefix:  make install PREFIX=~/.local

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
BINS    = noissh noisshd
TARGET  = target/release

.PHONY: build test check fmt clippy install uninstall clean

build:
	cargo build --release

test:
	cargo test --workspace

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt clippy test

install: build
	@mkdir -p "$(BINDIR)"
	@for b in $(BINS); do \
		install -m 0755 "$(TARGET)/$$b" "$(BINDIR)/$$b" && echo "installed $(BINDIR)/$$b"; \
	done

uninstall:
	@for b in $(BINS); do \
		rm -f "$(BINDIR)/$$b" && echo "removed $(BINDIR)/$$b"; \
	done

clean:
	cargo clean
