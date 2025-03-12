# Current contract directory
cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)

# Rust build settings
CUSTOM_RUSTFLAGS := -C debug-assertions
FULL_RUSTFLAGS := -C target-feature=+zba,+zbb,+zbc,+zbs,-a $(CUSTOM_RUSTFLAGS)
CARGO_ARGS :=
MODE := release
CLANG := $(shell $(TOP)/scripts/find_clang)
AR := $(subst clang,llvm-ar,$(CLANG))
OBJCOPY := $(subst clang,llvm-objcopy,$(CLANG))

# Output directory for binaries
BUILD_DIR :=
BINARIES := $(notdir $(shell pwd))

ifeq (release,$(MODE))
	MODE_ARGS := --release
endif

default: build test

build:
	@echo "🔧 Building contract in $(TOP)..."
	RUSTFLAGS="$(FULL_RUSTFLAGS)" TARGET_CC="$(CLANG)" TARGET_AR="$(AR)" \
		cargo build --target=riscv64imac-unknown-none-elf $(MODE_ARGS) $(CARGO_ARGS)
	@set -eu; \
	if [ "x$(BUILD_DIR)" != "x" ]; then \
		mkdir -p $(BUILD_DIR); \
		for binary in $(BINARIES); do \
			echo "📦 Copying binary $$binary to $(BUILD_DIR)"; \
			cp $(TOP)/target/riscv64imac-unknown-none-elf/$(MODE)/$$binary $(BUILD_DIR)/; \
			cp $(BUILD_DIR)/$$binary $(BUILD_DIR)/$$binary.debug; \
			$(OBJCOPY) --strip-debug --strip-all $(BUILD_DIR)/$$binary; \
		done \
	fi

test:
	cargo test $(CARGO_ARGS)

check:
	cargo check $(CARGO_ARGS)

clippy:
	cargo clippy $(CARGO_ARGS)

fmt:
	cargo fmt $(CARGO_ARGS)

cargo:
	cargo $(CARGO_CMD) $(CARGO_ARGS)

clean:
	cargo clean

prepare:
	rustup target add riscv64imac-unknown-none-elf

.PHONY: build test check clippy fmt cargo clean prepare
