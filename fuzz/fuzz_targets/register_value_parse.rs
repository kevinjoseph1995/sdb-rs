#![no_main]

use libfuzzer_sys::fuzz_target;
use libsdb::register_info::{REGISTER_INFO_TABLE, RegisterValue};

fuzz_target!(|input: &str| {
    for info in REGISTER_INFO_TABLE {
        let _ = RegisterValue::parse(input, info);
    }
});
