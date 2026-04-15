use std::fs;
use std::path::Path;

fn main() {
    let schema = Path::new("liquidity_pool.mol");
    let generated = Path::new("src/liquidity_pool_types.rs");

    println!("cargo:rerun-if-changed={}", schema.display());
    println!("cargo:rerun-if-changed={}", generated.display());

    if !generated.exists() {
        panic!(
            "Missing generated Molecule bindings at {}. Run `make -C crates/perun-common generate-liquidity-pool-types`.",
            generated.display()
        );
    }

    let schema_meta = fs::metadata(schema)
        .unwrap_or_else(|e| panic!("Failed to stat {}: {}", schema.display(), e));
    let generated_meta = fs::metadata(generated)
        .unwrap_or_else(|e| panic!("Failed to stat {}: {}", generated.display(), e));

    let schema_mtime = schema_meta
        .modified()
        .unwrap_or_else(|e| panic!("Failed to read mtime for {}: {}", schema.display(), e));
    let generated_mtime = generated_meta
        .modified()
        .unwrap_or_else(|e| panic!("Failed to read mtime for {}: {}", generated.display(), e));

    if generated_mtime < schema_mtime {
        panic!(
            "{} is older than {}. Regenerate bindings via `make -C crates/perun-common generate-liquidity-pool-types`.",
            generated.display(),
            schema.display()
        );
    }
}
