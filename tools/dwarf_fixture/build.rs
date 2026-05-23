fn main() {
    println!("cargo::rerun-if-changed=src/lib_a.c");
    println!("cargo::rerun-if-changed=src/lib_b.c");
    cc::Build::new()
        .file("src/lib_a.c")
        .file("src/lib_b.c")
        .flag("-g")
        .flag("-gdwarf-4")
        .flag("-O0")
        .compile("dwarf_fixture_lib");
}
