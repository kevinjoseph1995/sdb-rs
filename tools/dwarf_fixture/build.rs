use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=src/lib_a.c");
    println!("cargo::rerun-if-changed=src/lib_b.c");
    println!("cargo::rerun-if-changed=src/main.c");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"))
        .join("dwarf_fixture");

    // In a build script the cc crate has TARGET/OPT_LEVEL/HOST available, so it
    // resolves the right compiler and flags. `.compile()` would only produce a
    // static library, so reach for `get_compiler().to_command()` to link a
    // standalone executable instead.
    let status = cc::Build::new()
        .flag("-g")
        .flag("-gdwarf-4")
        .flag("-O0")
        .get_compiler()
        .to_command()
        .arg("src/lib_a.c")
        .arg("src/lib_b.c")
        .arg("src/main.c")
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to invoke the C compiler");
    assert!(status.success(), "DWARF fixture compile failed");

    // Bake the path into the crate so `fixture_path()` can hand it to tests.
    println!("cargo::rustc-env=DWARF_FIXTURE_BIN={}", out.display());
}
