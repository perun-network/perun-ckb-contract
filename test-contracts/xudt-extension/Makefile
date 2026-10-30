# Build a CKB dynamic library with the existing Rust toolchain and ckb-std.
TOP ?= $(abspath ../..)
MODE ?= release
MODE_ARGS = $(if $(filter release,$(MODE)),--release,)
BUILD_DIR ?= build/$(MODE)
RUST_LLD = $(shell rustc --print sysroot)/lib/rustlib/$(shell rustc -vV | sed -n 's/^host: //p')/bin/rust-lld

.PHONY: build
build:
	RUSTFLAGS="-C relocation-model=pic -C target-feature=+zba,+zbb,+zbc,+zbs,-a" \
		cargo build -p xudt-extension --target riscv64imac-unknown-none-elf $(MODE_ARGS)
	mkdir -p $(TOP)/$(BUILD_DIR)
	$(RUST_LLD) -flavor gnu -shared -z separate-code -z notext --no-undefined --gc-sections \
		--version-script=exports.map --undefined=validate -Bsymbolic \
		$(TOP)/target/riscv64imac-unknown-none-elf/$(MODE)/libxudt_extension.a \
		-o $(TOP)/$(BUILD_DIR)/xudt-extension
