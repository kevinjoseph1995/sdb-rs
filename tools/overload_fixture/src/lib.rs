//! Test-only crate for C++ overload tests.
//!
//! `build.rs` compiles a standalone C++ executable with three overloads of
//! `print_type` (see `src/main.cpp`) and records its path.

/// Absolute path to the compiled C++ overload fixture executable.
///
/// The path is baked in at build time by `build.rs` via `OVERLOAD_FIXTURE_BIN`.
pub fn fixture_path() -> &'static str {
    env!("OVERLOAD_FIXTURE_BIN")
}
