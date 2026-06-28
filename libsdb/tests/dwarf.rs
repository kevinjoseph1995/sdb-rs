use libsdb::{dwarf::Dwarf, elf::Elf};
use std::{path::PathBuf, rc::Rc};

// The fixture executable is compiled from C (lib_a.c / lib_b.c / main.c) by the
// `dwarf_fixture` dev-dependency's build script. Because it is a C-only binary,
// the DWARF under test is exactly our C, with no Rust `std` CUs mixed in.
#[test]
fn fixture_is_parsable_dwarf() {
    let path = PathBuf::from(dwarf_fixture::fixture_path());

    let elf = Elf::new(&path).expect("failed to parse fixture ELF");
    let dwarf = Dwarf::new(Rc::new(elf))
        .expect("failed to parse fixture DWARF")
        .expect("fixture should contain debug info");

    // lib_a.c and lib_b.c are separate translation units, so there should be at
    // least two compile units.
    assert!(
        dwarf.compile_units().len() >= 2,
        "expected at least 2 compile units, found {}",
        dwarf.compile_units().len(),
    );

    // Functions defined across both translation units (extern and static alike)
    // should be discoverable through the function index.
    for function in ["compute_a", "entry_a", "add_a", "entry_b", "sum_b"] {
        assert!(
            !dwarf.find_functions(function).is_empty(),
            "expected to find function `{function}` in fixture DWARF",
        );
    }
}
