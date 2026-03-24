# We cannot use $(shell pwd), which will return unix path format on Windows,
# making it hard to use.
cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

TOP := $(cur_dir)
CUSTOM_RUSTFLAGS := -C debug-assertions
FULL_RUSTFLAGS := -C target-feature=+zba,+zbb,+zbc,+zbs,-a $(CUSTOM_RUSTFLAGS)
CARGO_ARGS :=
MODE := release
CLANG := $(shell $(TOP)/scripts/find_clang)
AR := $(subst clang,llvm-ar,$(CLANG))
OBJCOPY := $(subst clang,llvm-objcopy,$(CLANG))
BUILD_DIR :=
BINARIES := $(notdir $(shell pwd))

ifeq (release,$(MODE))
	MODE_ARGS := --release
endif

default: build test

build:
	RUSTFLAGS="$(FULL_RUSTFLAGS)" TARGET_CC="$(CLANG)" TARGET_AR="$(AR)" \
		cargo build --target=riscv64imac-unknown-none-elf $(MODE_ARGS) $(CARGO_ARGS)
	@set -eu; \
	if [ "x$(BUILD_DIR)" != "x" ]; then \
		for binary in $(BINARIES); do \
			echo "Copying binary $$binary to build directory"; \
			cp $(TOP)/target/riscv64imac-unknown-none-elf/$(MODE)/$$binary $(TOP)/$(BUILD_DIR); \
			cp $(TOP)/$(BUILD_DIR)/$$binary $(TOP)/$(BUILD_DIR)/$$binary.debug; \
			$(OBJCOPY) --strip-debug --strip-all $(TOP)/$(BUILD_DIR)/$$binary; \
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

CARGO_CMD :=
cargo:
	cargo $(CARGO_CMD) $(CARGO_ARGS)

clean:
	cargo clean

prepare:
	rustup target add riscv64imac-unknown-none-elf

.PHONY: build test check clippy fmt cargo clean prepare
