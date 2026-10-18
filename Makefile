.PHONY: help bootstrap test test-real lint fmt check build build-target build-cli run bench dist clean
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

# Cross builds: PLATFORM=<name> (release.yml names) or TARGET=<triple>
# (TARGET wins); default is this host. Non-host targets build with
# cargo-zigbuild (`cargo install cargo-zigbuild`, needs zig). Windows uses
# the GNU ABI locally; release.yml builds MSVC binaries.
PLATFORM_linux-x64 := x86_64-unknown-linux-musl
PLATFORM_linux-arm64 := aarch64-unknown-linux-musl
PLATFORM_win-x64 := x86_64-pc-windows-gnu
PLATFORM_win-arm64 := aarch64-pc-windows-gnullvm
ifdef PLATFORM
TARGET ?= $(PLATFORM_$(PLATFORM))
ifeq ($(TARGET),)
$(error unknown PLATFORM=$(PLATFORM); use linux-x64, linux-arm64, win-x64, win-arm64 or TARGET=<triple>)
endif
endif
TARGET ?= $(HOST)
EXE := $(if $(findstring windows,$(TARGET)),.exe,)
CARGO_BUILD := $(if $(filter $(HOST),$(TARGET)),cargo build,cargo zigbuild)
TARGET_BIN := $(CARGO_TARGET_DIR)/$(TARGET)/dist/$(BIN)$(EXE)
# Host build -> bin/starpak; cross build -> bin/starpak-<platform|triple>.
OUT_BIN := bin/$(BIN)$(if $(filter $(HOST),$(TARGET)),,-$(or $(PLATFORM),$(TARGET)))$(EXE)

build: ## Build release binary (bin path: $(CARGO_TARGET_DIR)/release/$(BIN))
	STARPAK_VERSION=$(VERSION) cargo build --release -p starpak-cli

build-target:
	STARPAK_VERSION=$(VERSION) $(CARGO_BUILD) --profile dist -p starpak-cli --target $(TARGET)

build-cli: build-target ## Build the CLI into bin/ (PLATFORM=linux-x64|linux-arm64|win-x64|win-arm64 or TARGET=<triple>)
	mkdir -p bin
	cp $(TARGET_BIN) $(OUT_BIN)
	@echo $(OUT_BIN)

# make run ARGS="dcb records --path='*avenger*'"
run: ## Run the CLI against STARPAK_P4K (ARGS="...")
	STARPAK_VERSION=$(VERSION) cargo run --release -q -p starpak-cli -- $(ARGS)

bench: build ## Benchmark open/list/read and DataForge on STARPAK_P4K
	$(CARGO_TARGET_DIR)/release/$(BIN) bench
	$(CARGO_TARGET_DIR)/release/$(BIN) dcb bench

# release.yml builds every platform on tag push; this builds one locally.
dist: build-target ## Build a release archive into dist/ (PLATFORM= / TARGET= like build-cli)
	$(eval PKG := $(BIN)-$(VERSION)-$(or $(PLATFORM),$(TARGET)))
	rm -rf dist/$(PKG) && mkdir -p dist/$(PKG)
	cp README.md LICENSE $(TARGET_BIN) dist/$(PKG)/
	$(if $(EXE),cd dist && zip -qr $(PKG).zip $(PKG),tar czf dist/$(PKG).tar.gz -C dist $(PKG))
	rm -rf dist/$(PKG)
	@ls dist/$(PKG).*

clean: ## Clean build artifacts (target/, dist/, bin/)
	cargo clean
	rm -rf dist bin
