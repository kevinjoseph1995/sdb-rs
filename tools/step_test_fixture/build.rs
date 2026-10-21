use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=src/main.cpp");

    let out =
        PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set")).join("step_test_fixture");

    // `.compile()` only produces a static library, so reach for
    // `get_compiler().to_command()` to link a standalone executable instead.
    let status = cc::Build::new()
        .cpp(true)
        .flag("-g")
        .flag("-gdwarf-4")
        .flag("-O0")
        // Nix's compiler wrapper defines _FORTIFY_SOURCE after our flags, and
        // glibc warns about it in an unoptimized build. Silence that warning.
        .flag("-Wno-cpp")
        .get_compiler()
        .to_command()
        .arg("src/main.cpp")
        .arg("-o")
        .arg(&out)
        .status()
        .expect("failed to invoke the C++ compiler");
    assert!(status.success(), "overload fixture compile failed");

    println!("cargo::rustc-env=STEP_TEST_FIXTURE_BIN={}", out.display());
}
