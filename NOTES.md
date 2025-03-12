# Notes
## Goal
Migrate Capsule project into a project consistent with [CKP-script-templates](https://github.com/cryptape/ckb-script-templates).

## Steps
* Generated ckb-script workspace
* Copied script code from capsule project to workspace contracts folder
* Update dependencies
* Add tests

## Problems
To correctly generate the build files: we first need to set environment variables given in setup.env
Then to run `make test` we need to unset these variables again.
When running the automatically generated tests on x86_64-unknown-linux-gnu, we get errors like this:
`error[E0282]: type annotations needed
--> contracts/perun-channel-typescript/src/lib.rs:905:10
|
905 |         .unpack()[..]
|          ^^^^^^
|
help: try using a fully qualified path to specify the expected types
|
901 ~     if <Byte32 as ckb_std::ckb_gen_types::prelude::Unpack<T>>::unpack(&channel_constants
902 |         .params()
903 |         .party_a()
904 ~         .payment_script_hash())[..]
|
`
This means the x86_64-unknown-linux-gnu which is needed for testing needs type annotations, but these will in return break the build process.