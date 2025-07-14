fn main() {
    println!("cargo::rerun-if-changed=src/lib.cpp");
    cc::Build::new().cpp(true).file("src/lib.cpp").compile("lib");
}
