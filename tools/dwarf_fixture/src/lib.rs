//! Test-only crate for the DWARF tests.
//!
//! `build.rs` compiles a standalone, C-only executable rich in DWARF debug
//! info (see `src/lib_a.c` / `src/lib_b.c`) and records its path. `libsdb`
//! pulls this crate in as a dev-dependency, so the C compile only runs for
//! test builds and never when `libsdb` is built as a library.

/// Absolute path to the compiled C-only DWARF fixture executable.
///
/// The path is baked in at build time by `build.rs` via `DWARF_FIXTURE_BIN`.
pub fn fixture_path() -> &'static str {
    env!("DWARF_FIXTURE_BIN")
}
