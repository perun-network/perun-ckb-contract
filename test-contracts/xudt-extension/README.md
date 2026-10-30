# xUDT extension fixture

This Rust dynamic library is only for backend integration tests. It exports the
RFC 0052 `validate(owner, index, args, args_length)` ABI and uses `ckb-std` system
calls. It accepts extension index 0 with the one-byte argument `42`.

Owner mode permits fixture minting. Transfers require `channel-proof` in
`XudtWitness.extension_data[0]` and `channel-data` in `XudtData.data[0]` on every
group output. Witnesses and cell data are bounded to 2048 bytes for this fixture.
The checks deliberately have no authorization value outside these tests.

From the repository root:

```sh
make xudt-extension
cargo test -p xudt-extension
```

The build uses Cargo and the Rust toolchain's bundled linker to produce
`build/release/xudt-extension`. Only `validate` is exported; internal symbols
are local. `-z notext` allows the relative relocations emitted for Rust's
read-only data. There are no unresolved dynamic symbols or custom assembly.
The existing deployment format is provided in
`deployment/dev/deployment_xudt.toml`.
