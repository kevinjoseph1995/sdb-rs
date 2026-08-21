//! Test-only crate for the "no debug symbols" tests.
//!
//! `build.rs` compiles `src/main.c` twice: once without `-g` (no
//! `.debug_info`, but `.symtab` survives), and once with `-static -s` (no
//! `.debug_info` and no symbol table at all). `libsdb` pulls this crate in as
//! a dev-dependency, so the C compiles only run for test builds.

/// Absolute path to a binary with no `.debug_info` but an intact `.symtab`.
pub fn no_debug_fixture_path() -> &'static str {
    env!("NO_DEBUG_FIXTURE_BIN")
}

/// Absolute path to a fully stripped binary: no `.debug_info`, no `.symtab`,
/// no `.dynsym`.
pub fn stripped_fixture_path() -> &'static str {
    env!("STRIPPED_FIXTURE_BIN")
}
