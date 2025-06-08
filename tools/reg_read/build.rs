use std::{env, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    cc::Build::new().file("asm/reg_read.s").compile("reg_read");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=reg_read");
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rerun-if-changed=asm/reg_read.s");
}
