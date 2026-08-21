use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=src/main.c");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));

    // No `-g`: the binary carries no `.debug_info`, but its `.symtab` survives
    // since nothing strips it.
    let no_debug_out = out_dir.join("no_debug_fixture");
    let status = cc::Build::new()
        .flag("-O0")
        .debug(false)
        .get_compiler()
        .to_command()
        .arg("src/main.c")
        .arg("-o")
        .arg(&no_debug_out)
        .status()
        .expect("failed to invoke the C compiler");
    assert!(status.success(), "no_debug fixture compile failed");

    // `-s`: no `.debug_info`, and `.symtab` is stripped at link time. A
    // `.dynsym` still exists (dynamic linking needs it), but it only holds
    // imported/exported symbols — `main`/`add` are neither, so they can't be
    // found there either, simulating a stripped release binary.
    let stripped_out = out_dir.join("stripped_fixture");
    let status = cc::Build::new()
        .flag("-O0")
        .flag("-s")
        .debug(false)
        .get_compiler()
        .to_command()
        .arg("src/main.c")
        .arg("-o")
        .arg(&stripped_out)
        .status()
        .expect("failed to invoke the C compiler");
    assert!(status.success(), "stripped fixture compile failed");

    println!("cargo::rustc-env=NO_DEBUG_FIXTURE_BIN={}", no_debug_out.display());
    println!("cargo::rustc-env=STRIPPED_FIXTURE_BIN={}", stripped_out.display());
}
