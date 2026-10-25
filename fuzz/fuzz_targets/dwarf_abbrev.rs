#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    offset: u16,
    section: &'a [u8],
}

fuzz_target!(|input: Input| {
    let _ = libsdb::dwarf::fuzz_api::parse_abbrev_table(input.section, input.offset as usize);
});
