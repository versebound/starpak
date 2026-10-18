.PHONY: help bootstrap test test-real lint fmt check build build-cli run bench dist clean
.DEFAULT_GOAL := help

CARGO_TARGET_DIR ?= target
BIN := starpak
# Real-archive tests and `run`/`bench` read STARPAK_P4K (read-only). Set it
# in the environment or in an untracked local.mk.
-include local.mk
export STARPAK_P4K
# Version comes from the tag (vX.Y.Z), like the release workflow; untagged
# builds get git-describe output.
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null))
HOST := $(shell rustc -vV | sed -n 's/^host: //p')

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Fetch dependencies
	cargo fetch

test: ## Run hermetic tests
	cargo test --release

test-real: ## Run tests incl. the real-archive suite (STARPAK_P4K)
	STARPAK_TEST_P4K="$(STARPAK_P4K)" cargo test --release

lint: ## Run clippy (warnings as errors)
	cargo clippy --all-targets -- -D warnings

fmt: ## Check formatting
	cargo fmt --all --check

check: fmt lint test ## fmt + lint + test (what CI runs)

build: ## Build release binary (bin path: $(CARGO_TARGET_DIR)/release/$(BIN))
	STARPAK_VERSION=$(VERSION) cargo build --release -p starpak-cli

build-cli: build ## Build the CLI and copy it to bin/$(BIN)
	mkdir -p bin
	cp $(CARGO_TARGET_DIR)/release/$(BIN) bin/$(BIN)
	@echo bin/$(BIN)

# make run ARGS="dcb records --path='*avenger*'"
run: ## Run the CLI against STARPAK_P4K (ARGS="...")
	STARPAK_VERSION=$(VERSION) cargo run --release -q -p starpak-cli -- $(ARGS)

bench: build ## Benchmark open/list/read and DataForge on STARPAK_P4K
	$(CARGO_TARGET_DIR)/release/$(BIN) bench
	$(CARGO_TARGET_DIR)/release/$(BIN) dcb bench

# Host platform only; release.yml builds linux-x64/arm64 and win-x64/arm64
# on tag push. TARGET=<triple> builds another installed rustup target.
dist: ## Build a release archive for this host into dist/ (TARGET=<triple>)
	$(eval TARGET ?= $(HOST))
	$(eval PKG := $(BIN)-$(VERSION)-$(TARGET))
	STARPAK_VERSION=$(VERSION) cargo build --release -p starpak-cli --target $(TARGET)
	rm -rf dist/$(PKG) && mkdir -p dist/$(PKG)
	cp README.md LICENSE $(CARGO_TARGET_DIR)/$(TARGET)/release/$(BIN) dist/$(PKG)/
	tar czf dist/$(PKG).tar.gz -C dist $(PKG)
	rm -rf dist/$(PKG)
	@echo dist/$(PKG).tar.gz

clean: ## Clean build artifacts (target/, dist/, bin/)
	cargo clean
	rm -rf dist bin
