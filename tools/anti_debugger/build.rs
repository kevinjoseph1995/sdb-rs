fn main() {
    println!("cargo::rerun-if-changed=src/lib.cpp");
    cc::Build::new()
        .cpp(true)
        // Nix's compiler wrapper defines _FORTIFY_SOURCE after our flags, and
        // glibc warns about it in an unoptimized build. Silence that warning.
        .flag("-Wno-cpp")
        .file("src/lib.cpp")
        .compile("lib");
}
