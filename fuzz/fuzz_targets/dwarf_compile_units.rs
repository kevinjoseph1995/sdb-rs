#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = libsdb::dwarf::fuzz_api::parse_compile_units(data);
});
