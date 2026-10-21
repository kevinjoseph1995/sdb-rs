/// Absolute path to the compiled C++ overload fixture executable.
///
/// The path is baked in at build time by `build.rs` via `STEP_TEST_FIXTURE_BIN`.
pub fn fixture_path() -> &'static str {
    env!("STEP_TEST_FIXTURE_BIN")
}

/// Absolute path to the fixture's C++ source, for looking up `// MARK:<name>`
/// comments.
pub fn source_path() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.cpp")
}

/// The 1-based line number of the `// MARK:<name>` comment in the source.
pub fn marked_line(name: &str) -> usize {
    let tag = format!("// MARK:{name}");
    let source = std::fs::read_to_string(source_path()).expect("failed to read fixture source");
    source
        .lines()
        .position(|line| line.trim_end().ends_with(&tag))
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("no `{tag}` marker in the fixture source"))
}
