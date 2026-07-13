//! Generates the committed C header `include/adapt_e2e_core.h` from the
//! `extern "C"` surface via cbindgen (SPEC §1, §2), gated behind the
//! `generate-header` feature so it is host-only tooling and never runs during
//! normal / `no_std` / rv32 (`-Zbuild-std`) target builds. The header is
//! committed for consumers; regenerate with `cargo build --features generate-header`.

fn main() {
    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/mgmt/error.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    #[cfg(feature = "generate-header")]
    generate_header();
}

#[cfg(feature = "generate-header")]
fn generate_header() {
    let crate_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };
    let out = std::path::Path::new(&crate_dir).join("include/adapt_e2e_core.h");
    let config = cbindgen::Config::from_root_or_default(&crate_dir);
    match cbindgen::Builder::new().with_crate(&crate_dir).with_config(config).generate() {
        Ok(bindings) => {
            let _ = std::fs::create_dir_all(std::path::Path::new(&crate_dir).join("include"));
            bindings.write_to_file(&out);
        }
        Err(e) => println!("cargo:warning=cbindgen header generation skipped: {e}"),
    }
}
