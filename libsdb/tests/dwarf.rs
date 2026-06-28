use libsdb::{
    dwarf::{Die::NonNull, Dwarf},
    dwarf_constants::{DwAt, DwLang, DwTag},
    elf::Elf,
};
use std::{ffi::CStr, path::PathBuf, rc::Rc, sync::LazyLock, thread::LocalKey};

fn get_test_fixture() -> &'static LocalKey<Dwarf> {
    thread_local! {
        static ELF : LazyLock<Rc<Elf>> = LazyLock::new(||{
            let path = PathBuf::from(dwarf_fixture::fixture_path());
            println!("{:#?}", path);
            Rc::new(Elf::new(&path).expect("failed to parse fixture ELF"))
        });
    }
    thread_local! {
        static DWARF : Dwarf = ELF.with(|elf| {
            Dwarf::new(Rc::clone(&*elf))
                .expect("failed to parse fixture DWARF")
                .expect("fixture should contain debug info")
        });
    }
    return &DWARF;
}

// The fixture executable is compiled from C (lib_a.c / lib_b.c / main.c) by the
// `dwarf_fixture` dev-dependency's build script. Because it is a C-only binary,
// the DWARF under test is exactly our C, with no Rust `std` CUs mixed in.

#[test]
fn test_dwarf_correct_number_of_compile_units() {
    get_test_fixture().with(|dwarf| {
        // lib_a.c and lib_b.c are separate translation units, so there should be at
        // least two compile units.
        assert!(
            dwarf.compile_units().len() == 3,
            "expected 3 compile units, found {}",
            dwarf.compile_units().len(),
        );
    });
}

#[test]
fn test_dwarf_correct_dwarf_language() {
    get_test_fixture().with(|dwarf| {
        let root = dwarf
            .root_of(0)
            .expect("Failed to get the root of the 0'th compile unit");
        let attr = root
            .get_attr(DwAt::Language as u64)
            .expect("Failed to get the Language attr of the 0th compile unit");
        // ISO C99 (the 1999 standard)
        assert_eq!(
            DwLang::C99 as u64,
            attr.as_int().expect("Attr is not a int attr")
        );
    });
}

#[test]
fn test_dwarf_iterate_die() {
    get_test_fixture().with(|dwarf| {
        for (cu_index, _compile_unit) in dwarf.compile_units().iter().enumerate() {
            let root = dwarf.root_of(cu_index).expect(&format!(
                "Failed to get root of compile unit index={}",
                cu_index
            ));
            let mut child_count = 0;
            for child_die in root.children().expect("Expected root to have children") {
                let child_die = child_die.expect("Parsing of DIE failed");
                if let NonNull(payload) = child_die {
                    assert_ne!(payload.abbrev_code(), 0u64);
                } else {
                    panic!("Found null DIE");
                }
                child_count += 1;
            }
            assert!(child_count > 0);
        }
    });
}

#[test]
fn test_dwarf_find_main() {
    get_test_fixture().with(|dwarf| {
        assert!(
            dwarf
                .compile_units()
                .iter() // Iterate through all compile units
                .enumerate()
                .flat_map(|(cu_index, _compile_unit)| {
                    let root = dwarf.root_of(cu_index).expect("Failed to get root");
                    root.children().expect("Failed to get children off root")
                })
                .map(|die| die.expect("DIE parsing failed"))
                .find(|die| match die {
                    libsdb::dwarf::Die::Null(_) => false,
                    NonNull(die_payload) => {
                        if let Some(name_attr) = die.get_attr(DwAt::Name as u64) {
                            if die_payload.tag() == DwTag::Subprogram as u64 {
                                let name = name_attr
                                    .as_string()
                                    .expect("Failed to interpret attr as string");
                                return name == CStr::from_bytes_with_nul(b"main\0").unwrap();
                            }
                        }
                        return false;
                    }
                })
                .is_some()
        );
    });
}
