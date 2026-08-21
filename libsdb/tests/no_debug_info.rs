use libsdb::{dwarf::Dwarf, elf::Elf, target::Target};
use std::{
    ffi::{CStr, CString},
    path::PathBuf,
    rc::Rc,
};

// These tests exercise the "no debug symbols" paths that `dwarf_fixture`-based
// tests never touch. `no_debug_fixture` (see `tools/no_debug_fixture`) compiles
// a tiny C program two ways: once without `-g` (no `.debug_info`, but its
// `.symtab` survives), and once with `-static -s` (no `.debug_info` and no
// symbol table at all), simulating a fully stripped release binary.

#[test]
fn dwarf_new_returns_none_without_debug_info_section() {
    let path = PathBuf::from(no_debug_fixture::no_debug_fixture_path());
    let elf = Rc::new(Elf::new(&path).expect("failed to parse ELF"));

    let dwarf = Dwarf::new(Rc::clone(&elf))
        .expect("Dwarf::new should not error just because `.debug_info` is absent");

    assert!(
        dwarf.is_none(),
        "Dwarf::new should return None when `.debug_info` is absent"
    );
}

#[test]
fn elf_parses_stripped_binary_with_empty_symbol_table() {
    let path = PathBuf::from(no_debug_fixture::stripped_fixture_path());
    let elf = Elf::new(&path).expect("Elf::new should not fail on a fully stripped binary");

    assert!(
        elf.get_section_header_by_name(CStr::from_bytes_with_nul(b".debug_info\0").unwrap())
            .is_none(),
        "stripped fixture should not carry `.debug_info`"
    );
    assert!(
        elf.get_section_header_by_name(CStr::from_bytes_with_nul(b".symtab\0").unwrap())
            .is_none(),
        "stripped fixture should not carry `.symtab`"
    );

    // `.dynsym` (needed for dynamic linking) may still be present, but it
    // only holds imported/exported symbols — neither `main` nor `add` is
    // exported, so lookups for them should come back empty either way.
    let main = CString::new("main").unwrap();
    let add = CString::new("add").unwrap();
    assert!(
        elf.get_symbols_with_name(&main).is_empty(),
        "symbol lookup against a stripped binary should return no matches, not error"
    );
    assert!(
        elf.get_symbols_with_name(&add).is_empty(),
        "symbol lookup against a stripped binary should return no matches, not error"
    );
}

#[test]
fn target_launch_succeeds_with_no_dwarf() {
    let path = PathBuf::from(no_debug_fixture::no_debug_fixture_path());
    let target = Target::launch(&path, None, true, None)
        .expect("Target::launch should succeed on a binary without debug info");

    assert!(
        target.state.dwarf.is_none(),
        "no_debug fixture has no `.debug_info`, so Target should carry no Dwarf"
    );
}

#[test]
fn step_in_fails_cleanly_without_dwarf() {
    let path = PathBuf::from(no_debug_fixture::no_debug_fixture_path());
    let mut target = Target::launch(&path, None, true, None)
        .expect("failed to launch no_debug fixture");

    let result = target.step_in();
    assert!(
        result.is_err(),
        "step_in should return an Err (not panic) when there is no DWARF info: {result:?}"
    );
}

#[test]
fn step_over_fails_cleanly_without_dwarf() {
    let path = PathBuf::from(no_debug_fixture::no_debug_fixture_path());
    let mut target = Target::launch(&path, None, true, None)
        .expect("failed to launch no_debug fixture");

    let result = target.step_over();
    assert!(
        result.is_err(),
        "step_over should return an Err (not panic) when there is no DWARF info: {result:?}"
    );
}

/// `step_out` doesn't actually need DWARF for the common case: it walks the
/// return address off the current frame pointer (`rbp + 8`) rather than
/// consulting the inline-frame stack, so it should keep working even on a
/// binary with no debug info at all.
#[test]
fn step_out_still_works_without_dwarf() {
    let path = PathBuf::from(no_debug_fixture::no_debug_fixture_path());
    let mut target =
        Target::launch(&path, None, true, None).expect("failed to launch no_debug fixture");

    let add_name = CString::new("add").unwrap();
    let add_symbol = target
        .state
        .elf
        .get_symbols_with_name(&add_name)
        .into_iter()
        .next()
        .expect("no_debug fixture's `.symtab` should still contain `add`");
    let add_low_pc = libsdb::address::FileAddress::new(&target.state.elf, add_symbol.st_value as usize)
        .to_virt_address()
        .expect("`add`'s file address should map into the running process");

    target
        .process
        .run_until_address(add_low_pc)
        .expect("failed to run to `add`");

    // Land past `add`'s prologue (`push rbp; mov rbp, rsp` — two
    // instructions) so `rbp` actually points at `add`'s frame rather than
    // its caller's; step_out's frame-pointer walk depends on that.
    target
        .process
        .step_instruction()
        .expect("failed to step past `push rbp`");
    target
        .process
        .step_instruction()
        .expect("failed to step past `mov rbp, rsp`");

    let reason = target.step_out().expect("step_out should succeed without DWARF");
    assert!(
        reason.is_step(),
        "step_out stopped for an unexpected reason: {:?}",
        reason.wait_status
    );
}
