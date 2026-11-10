//! Builds both guest ELFs from `program/` with sp1-build:
//!
//! - `orc-program`          production (GitHub trust anchors hardcoded)
//! - `orc-program-test-ca`  TEST ONLY (`--features test-ca`, tlsn test CA)
//!
//! sp1-build compiles every variant to the same path
//! (`<target>/elf-compilation/.../release/orc-program`), and its
//! `SP1_ELF_orc-program` env var points there, so `include_elf!` would see
//! whichever variant was built last. Each build therefore copies its ELF to
//! `$OUT_DIR/elf/<name>` right away; main.rs `include_bytes!`es those copies.

use std::path::PathBuf;

use sp1_build::{BuildArgs, build_program_with_args};

const PROGRAM_DIR: &str = "../../program";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("elf");
    let out_dir = out_dir.to_str().expect("utf-8 OUT_DIR").to_owned();

    build(&out_dir, "orc-program", &[]);
    build(&out_dir, "orc-program-test-ca", &["test-ca"]);
}

fn build(out_dir: &str, elf_name: &str, features: &[&str]) {
    build_program_with_args(
        PROGRAM_DIR,
        BuildArgs {
            features: features.iter().map(|f| (*f).to_owned()).collect(),
            output_directory: Some(out_dir.to_owned()),
            elf_name: Some(elf_name.to_owned()),
            // program/Cargo.lock is part of the vkey: never re-resolve it here.
            locked: true,
            ..Default::default()
        },
    );
}
