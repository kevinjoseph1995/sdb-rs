use libsdb::{
    address::FileAddress,
    dwarf::{Die, Die::NonNull, Dwarf},
    dwarf_constants::{DwAt, DwAte, DwForm, DwLang, DwTag},
    elf::Elf,
};
use std::{
    collections::HashMap,
    ffi::{CStr, OsStr},
    path::PathBuf,
    rc::Rc,
    sync::LazyLock,
    thread::LocalKey,
};

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
// the DWARF under test is exactly our C, with no Rust `std` CUs mixed in. The
// expected values asserted below are hand-derived from those three sources.

// --- Test helpers -------------------------------------------------------------

/// Depth-first search across every CU (root + all descendants) for the first DIE
/// matching `pred`. The returned `Die` borrows `dwarf`, so it outlives the walk.
fn find_die<'dw>(dwarf: &'dw Dwarf, pred: &dyn Fn(&Die<'dw>) -> bool) -> Option<Die<'dw>> {
    for cu_index in 0..dwarf.compile_units().len() {
        let root = dwarf
            .root_of(cu_index)
            .unwrap_or_else(|e| panic!("root_of({cu_index}) failed: {e:?}"));
        if let Some(found) = find_in_subtree(root, pred) {
            return Some(found);
        }
    }
    None
}

fn find_in_subtree<'dw>(die: Die<'dw>, pred: &dyn Fn(&Die<'dw>) -> bool) -> Option<Die<'dw>> {
    if pred(&die) {
        return Some(die);
    }
    let children = match die.children() {
        Some(children) => children,
        None => return None,
    };
    for child in children {
        let child = child.expect("failed to parse child DIE");
        if let Some(found) = find_in_subtree(child, pred) {
            return Some(found);
        }
    }
    None
}

/// First DIE anywhere in the program with the given tag and `DW_AT_name`.
fn find_named<'dw>(dwarf: &'dw Dwarf, tag: DwTag, name: &str) -> Option<Die<'dw>> {
    find_die(dwarf, &|die| {
        die.tag() == Some(tag as u64) && die.name().as_deref() == Some(name)
    })
}

/// First direct child of `die` with the given tag and `DW_AT_name`.
fn child_named<'dw>(die: &Die<'dw>, tag: DwTag, name: &str) -> Option<Die<'dw>> {
    for child in die.children()? {
        let child = child.expect("failed to parse child DIE");
        if child.tag() == Some(tag as u64) && child.name().as_deref() == Some(name) {
            return Some(child);
        }
    }
    None
}

/// Resolves a DIE's `DW_AT_type` reference to the type DIE it points at.
fn follow_type<'dw>(die: &Die<'dw>) -> Die<'dw> {
    die.get_attr(DwAt::Type as u64)
        .expect("DIE has a DW_AT_type attribute")
        .as_reference()
        .expect("DW_AT_type resolves to a DIE")
}

/// Collects every direct child of `die` carrying the given tag.
fn children_of_tag<'dw>(die: &Die<'dw>, tag: DwTag) -> Vec<Die<'dw>> {
    let mut out = Vec::new();
    if let Some(children) = die.children() {
        for child in children {
            let child = child.expect("failed to parse child DIE");
            if child.tag() == Some(tag as u64) {
                out.push(child);
            }
        }
    }
    out
}

/// Names of every direct child of `die` carrying the given tag, in order.
fn child_names(die: &Die<'_>, tag: DwTag) -> Vec<String> {
    children_of_tag(die, tag)
        .iter()
        .map(|c| c.name().expect("child has a name"))
        .collect()
}

/// Reads `die`'s attribute `at` as an integer.
fn int_attr(die: &Die<'_>, at: DwAt) -> u64 {
    die.get_attr(at as u64)
        .unwrap_or_else(|| panic!("DIE missing attribute {:#x}", at as u64))
        .as_int()
        .expect("attribute decodes as an int")
}

/// Functions defined (not merely declared) in the fixture, each carrying a
/// low/high PC. `add_a` and `sum_b` are `static`; the rest are `extern`.
const DEFINED_FUNCTIONS: &[&str] = &["entry_a", "compute_a", "add_a", "entry_b", "sum_b", "main"];

// --- Compile units ------------------------------------------------------------

#[test]
fn test_dwarf_correct_number_of_compile_units() {
    get_test_fixture().with(|dwarf| {
        // lib_a.c, lib_b.c and main.c are separate translation units.
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
fn test_dwarf_compile_units_identify_sources() {
    get_test_fixture().with(|dwarf| {
        let mut names: Vec<String> = (0..dwarf.compile_units().len())
            .map(|cu_index| {
                let root = dwarf.root_of(cu_index).expect("Failed to get CU root");
                assert_eq!(
                    root.tag(),
                    Some(DwTag::CompileUnit as u64),
                    "every CU root is a DW_TAG_compile_unit"
                );
                // Every fixture translation unit is compiled as C99.
                let lang = root
                    .get_attr(DwAt::Language as u64)
                    .expect("CU has DW_AT_language");
                assert_eq!(lang.as_int().expect("language is an int"), DwLang::C99 as u64);
                // The CU name comes from .debug_str (DW_FORM_strp).
                root.name().expect("CU has a DW_AT_name")
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["src/lib_a.c", "src/lib_b.c", "src/main.c"]);
    });
}

// --- DIE iteration ------------------------------------------------------------

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

// --- Function index / address lookups ----------------------------------------

#[test]
fn test_dwarf_find_functions_locates_definitions() {
    get_test_fixture().with(|dwarf| {
        for &name in DEFINED_FUNCTIONS {
            let dies = dwarf.find_functions(name);
            assert!(!dies.is_empty(), "expected to find function `{name}`");
            for die in &dies {
                assert_eq!(
                    die.tag(),
                    Some(DwTag::Subprogram as u64),
                    "`{name}` should be a DW_TAG_subprogram"
                );
                let low = die
                    .low_pc()
                    .unwrap_or_else(|e| panic!("`{name}` low_pc: {e:?}"));
                let high = die
                    .high_pc()
                    .unwrap_or_else(|e| panic!("`{name}` high_pc: {e:?}"));
                // DW_AT_high_pc is encoded as an offset from low_pc in this fixture.
                assert!(low < high, "`{name}`: low_pc {low} should be < high_pc {high}");
                assert_ne!(low.address, 0, "`{name}` low_pc should be nonzero");
            }
        }
    });
}

#[test]
fn test_dwarf_find_functions_unknown_is_empty() {
    get_test_fixture().with(|dwarf| {
        assert!(dwarf.find_functions("no_such_function_xyz").is_empty());
    });
}

#[test]
fn test_dwarf_function_containing_address() {
    get_test_fixture().with(|dwarf| {
        let compute_a = dwarf.find_functions("compute_a");
        let low = compute_a
            .first()
            .expect("compute_a is defined")
            .low_pc()
            .expect("compute_a low_pc");

        let found = dwarf
            .function_containing_address(low)
            .expect("an address inside compute_a resolves to a function");
        assert_eq!(found.tag(), Some(DwTag::Subprogram as u64));
        assert_eq!(found.name().as_deref(), Some("compute_a"));

        // An address far above every function maps to no function.
        let outside = FileAddress::new(dwarf.elf(), 0xffff_ffff);
        assert!(dwarf.function_containing_address(outside).is_none());
    });
}

#[test]
fn test_dwarf_compile_unit_containing_address() {
    get_test_fixture().with(|dwarf| {
        let low = dwarf
            .find_functions("compute_a")
            .first()
            .expect("compute_a is defined")
            .low_pc()
            .expect("compute_a low_pc");

        let cu_index = dwarf
            .compile_unit_containing_address(low)
            .expect("compute_a's address belongs to a compile unit");
        // compute_a is defined in lib_a.c.
        let name = dwarf
            .root_of(cu_index)
            .expect("CU root")
            .name()
            .expect("CU name");
        assert_eq!(name, "src/lib_a.c");
    });
}

// --- Attribute forms ----------------------------------------------------------

#[test]
fn test_dwarf_enumeration_const_values() {
    get_test_fixture().with(|dwarf| {
        let color_a =
            find_named(dwarf, DwTag::EnumerationType, "color_a").expect("color_a enum present");

        let mut values = HashMap::new();
        for enumerator in color_a.children().expect("enum has children") {
            let enumerator = enumerator.expect("enumerator parse");
            if enumerator.tag() != Some(DwTag::Enumerator as u64) {
                continue;
            }
            let name = enumerator.name().expect("enumerator name");
            let value = enumerator
                .get_attr(DwAt::ConstValue as u64)
                .expect("enumerator DW_AT_const_value")
                .as_int()
                .expect("const value as int");
            values.insert(name, value);
        }

        // DW_FORM_data1
        assert_eq!(values["COLOR_A_RED"], 0);
        assert_eq!(values["COLOR_A_GREEN"], 1);
        // DW_FORM_data4
        assert_eq!(values["COLOR_A_BLUE"], 0x7fff_ffff);
        // DW_FORM_sdata: -1 sign-extends into the u64 `as_int` returns.
        assert_eq!(values["COLOR_A_NEG"], (-1i64) as u64);
    });
}

#[test]
fn test_dwarf_struct_members_and_bitfields() {
    get_test_fixture().with(|dwarf| {
        let flags_a =
            find_named(dwarf, DwTag::StructureType, "flags_a").expect("flags_a struct present");

        let members: Vec<String> = flags_a
            .children()
            .expect("struct has members")
            .map(|m| m.expect("member parse"))
            .filter(|m| m.tag() == Some(DwTag::Member as u64))
            .map(|m| m.name().expect("member name"))
            .collect();
        assert_eq!(members, vec!["a_low", "a_high", "a_wide", "a_word"]);

        // The bit-field members carry DW_AT_bit_size (DW_FORM_data1).
        let a_low = child_named(&flags_a, DwTag::Member, "a_low").expect("a_low member");
        assert_eq!(
            a_low
                .get_attr(DwAt::BitSize as u64)
                .expect("a_low DW_AT_bit_size")
                .as_int()
                .expect("bit_size as int"),
            3
        );
        let a_high = child_named(&flags_a, DwTag::Member, "a_high").expect("a_high member");
        assert_eq!(
            a_high
                .get_attr(DwAt::BitSize as u64)
                .expect("a_high DW_AT_bit_size")
                .as_int()
                .expect("bit_size as int"),
            5
        );

        // A member's DW_AT_type resolves (DW_FORM_ref4) to a named type DIE.
        let a_wide = child_named(&flags_a, DwTag::Member, "a_wide").expect("a_wide member");
        assert_eq!(follow_type(&a_wide).name().as_deref(), Some("uint16_t"));
    });
}

#[test]
fn test_dwarf_typedef_chain_resolves() {
    get_test_fixture().with(|dwarf| {
        // flags_alias_t -> flags_a_t -> struct flags_a
        let alias =
            find_named(dwarf, DwTag::Typedef, "flags_alias_t").expect("flags_alias_t typedef");

        let flags_a_t = follow_type(&alias);
        assert_eq!(flags_a_t.tag(), Some(DwTag::Typedef as u64));
        assert_eq!(flags_a_t.name().as_deref(), Some("flags_a_t"));

        let flags_a = follow_type(&flags_a_t);
        assert_eq!(flags_a.tag(), Some(DwTag::StructureType as u64));
        assert_eq!(flags_a.name().as_deref(), Some("flags_a"));
    });
}

#[test]
fn test_dwarf_self_referential_struct() {
    get_test_fixture().with(|dwarf| {
        // node_b.next is a `struct node_b *`, so following its type twice lands
        // back on the node_b structure DIE (a CU-local DW_AT_type reference).
        let node_b = find_named(dwarf, DwTag::StructureType, "node_b").expect("node_b struct");

        let next = child_named(&node_b, DwTag::Member, "next").expect("next member");
        let ptr = follow_type(&next);
        assert_eq!(ptr.tag(), Some(DwTag::PointerType as u64));

        let pointee = follow_type(&ptr);
        assert_eq!(pointee.tag(), Some(DwTag::StructureType as u64));
        assert_eq!(pointee.name().as_deref(), Some("node_b"));
    });
}

#[test]
fn test_dwarf_global_variable_location() {
    get_test_fixture().with(|dwarf| {
        // The fixture (GCC, DWARF 4) emits variable locations as DW_FORM_exprloc.
        let hello = find_named(dwarf, DwTag::Variable, "hello_a").expect("hello_a global");
        let location = hello
            .get_attr(DwAt::Location as u64)
            .expect("hello_a has DW_AT_location");
        assert_eq!(location.form(), DwForm::Exprloc as u64);
    });
}

#[test]
fn test_dwarf_name_string_forms() {
    get_test_fixture().with(|dwarf| {
        // DW_FORM_string: short base-type names are stored inline in .debug_info.
        let int_type = find_named(dwarf, DwTag::BaseType, "int").expect("int base type");
        let inline = int_type
            .get_attr(DwAt::Name as u64)
            .expect("base type has DW_AT_name");
        assert_eq!(inline.form(), DwForm::String as u64);
        assert_eq!(
            inline.as_string().expect("inline string").to_str().unwrap(),
            "int"
        );

        // DW_FORM_strp: the CU name is an offset into .debug_str.
        let root = dwarf.root_of(0).expect("CU root");
        let strp = root
            .get_attr(DwAt::Name as u64)
            .expect("CU has DW_AT_name");
        assert_eq!(strp.form(), DwForm::Strp as u64);
        assert!(
            strp.as_string()
                .expect("strp string")
                .to_str()
                .unwrap()
                .ends_with(".c")
        );
    });
}

#[test]
fn test_dwarf_base_type_encodings() {
    get_test_fixture().with(|dwarf| {
        // (name, byte_size, encoding) hand-read from the fixture's base types.
        let expected: &[(&str, u64, DwAte)] = &[
            ("int", 4, DwAte::Signed),
            ("char", 1, DwAte::SignedChar),
            ("unsigned int", 4, DwAte::Unsigned),
            ("float", 4, DwAte::Float),
            ("long int", 8, DwAte::Signed),
            ("double", 8, DwAte::Float), // only appears in lib_b.c
        ];
        for &(name, byte_size, encoding) in expected {
            let die = find_named(dwarf, DwTag::BaseType, name)
                .unwrap_or_else(|| panic!("base type `{name}` present"));
            assert_eq!(int_attr(&die, DwAt::ByteSize), byte_size, "{name} byte_size");
            assert_eq!(int_attr(&die, DwAt::Encoding), encoding as u64, "{name} encoding");
        }
    });
}

#[test]
fn test_dwarf_struct_byte_sizes() {
    get_test_fixture().with(|dwarf| {
        // sizeof from the C declarations (LP64).
        for &(name, size) in &[("flags_a", 8u64), ("node_b", 24), ("pair_b", 32)] {
            let die = find_named(dwarf, DwTag::StructureType, name)
                .unwrap_or_else(|| panic!("struct `{name}` present"));
            assert_eq!(int_attr(&die, DwAt::ByteSize), size, "{name} byte_size");
        }
    });
}

#[test]
fn test_dwarf_member_data_locations() {
    get_test_fixture().with(|dwarf| {
        // struct node_b { int value; struct node_b *next; double weight; }
        let node_b = find_named(dwarf, DwTag::StructureType, "node_b").expect("node_b struct");
        let offsets: Vec<(String, u64)> = children_of_tag(&node_b, DwTag::Member)
            .iter()
            .map(|m| {
                (
                    m.name().expect("member name"),
                    int_attr(m, DwAt::DataMemberLocation),
                )
            })
            .collect();
        assert_eq!(
            offsets,
            vec![
                ("value".to_string(), 0),
                ("next".to_string(), 8),
                ("weight".to_string(), 16),
            ]
        );

        // struct pair_b { struct node_b head; enum mode_b mode; }
        let pair_b = find_named(dwarf, DwTag::StructureType, "pair_b").expect("pair_b struct");
        let head = child_named(&pair_b, DwTag::Member, "head").expect("head member");
        let mode = child_named(&pair_b, DwTag::Member, "mode").expect("mode member");
        assert_eq!(int_attr(&head, DwAt::DataMemberLocation), 0);
        assert_eq!(int_attr(&mode, DwAt::DataMemberLocation), 24);
    });
}

#[test]
fn test_dwarf_union_type() {
    get_test_fixture().with(|dwarf| {
        let maybe_a = find_named(dwarf, DwTag::UnionType, "maybe_a").expect("maybe_a union");
        // A union is as wide as its widest member (the pointer / 8 bytes here).
        assert_eq!(int_attr(&maybe_a, DwAt::ByteSize), 8);
        assert_eq!(
            child_names(&maybe_a, DwTag::Member),
            vec!["as_int", "as_float", "as_ptr"]
        );
        // Every union member starts at offset 0 (no DW_AT_data_member_location).
        for member in children_of_tag(&maybe_a, DwTag::Member) {
            assert!(member.get_attr(DwAt::DataMemberLocation as u64).is_none());
        }
    });
}

#[test]
fn test_dwarf_enumeration_mode_b() {
    get_test_fixture().with(|dwarf| {
        // enum mode_b has an unsigned underlying type (it has a large positive value).
        let mode_b =
            find_named(dwarf, DwTag::EnumerationType, "mode_b").expect("mode_b enum present");
        assert_eq!(int_attr(&mode_b, DwAt::Encoding), DwAte::Unsigned as u64);

        let mut values = HashMap::new();
        for e in children_of_tag(&mode_b, DwTag::Enumerator) {
            values.insert(e.name().expect("enumerator name"), int_attr(&e, DwAt::ConstValue));
        }
        assert_eq!(values["MODE_B_OFF"], 0);
        assert_eq!(values["MODE_B_ON"], 1);
        assert_eq!(values["MODE_B_PULSED"], 0xabcd);
    });
}

#[test]
fn test_dwarf_array_type_dimensions() {
    get_test_fixture().with(|dwarf| {
        // `static const int matrix_a[3][4]` -> const -> array with two subranges.
        let matrix = find_named(dwarf, DwTag::Variable, "matrix_a").expect("matrix_a variable");
        let const_ty = follow_type(&matrix);
        assert_eq!(const_ty.tag(), Some(DwTag::ConstType as u64));
        let array_ty = follow_type(&const_ty);
        assert_eq!(array_ty.tag(), Some(DwTag::ArrayType as u64));

        // DW_AT_upper_bound is one less than the dimension length.
        let bounds: Vec<u64> = children_of_tag(&array_ty, DwTag::SubrangeType)
            .iter()
            .map(|s| int_attr(s, DwAt::UpperBound))
            .collect();
        assert_eq!(bounds, vec![2, 3]); // [3][4]

        // The element type is `const int`: a const_type wrapping the int base type.
        let element = follow_type(&array_ty);
        assert_eq!(element.tag(), Some(DwTag::ConstType as u64));
        assert_eq!(follow_type(&element).name().as_deref(), Some("int"));
    });
}

#[test]
fn test_dwarf_subroutine_type_signature() {
    get_test_fixture().with(|dwarf| {
        // typedef int (*binop_a)(int, int) -> pointer -> subroutine_type.
        let binop = find_named(dwarf, DwTag::Typedef, "binop_a").expect("binop_a typedef");
        let ptr = follow_type(&binop);
        assert_eq!(ptr.tag(), Some(DwTag::PointerType as u64));
        let subr = follow_type(&ptr);
        assert_eq!(subr.tag(), Some(DwTag::SubroutineType as u64));

        // Returns int, takes two unnamed int parameters.
        assert_eq!(follow_type(&subr).name().as_deref(), Some("int"));
        let params = children_of_tag(&subr, DwTag::FormalParameter);
        assert_eq!(params.len(), 2);
        for p in &params {
            assert_eq!(follow_type(p).name().as_deref(), Some("int"));
        }
    });
}

#[test]
fn test_dwarf_subprogram_formal_parameters() {
    get_test_fixture().with(|dwarf| {
        // int compute_a(flags_alias_t *f, enum color_a c, union maybe_a *m, binop_a op)
        let compute_a = dwarf.find_functions("compute_a");
        let compute_a = compute_a.first().expect("compute_a defined");
        assert_eq!(
            child_names(compute_a, DwTag::FormalParameter),
            vec!["f", "c", "m", "op"]
        );
        // compute_a returns int.
        assert_eq!(follow_type(compute_a).name().as_deref(), Some("int"));

        // add_a(int x, int y)
        let add_a = dwarf.find_functions("add_a");
        let add_a = add_a.first().expect("add_a defined");
        assert_eq!(child_names(add_a, DwTag::FormalParameter), vec!["x", "y"]);
    });
}

#[test]
fn test_dwarf_external_vs_static_linkage() {
    get_test_fixture().with(|dwarf| {
        // extern functions carry DW_AT_external (DW_FORM_flag_present).
        for name in ["compute_a", "entry_a", "entry_b", "main"] {
            let dies = dwarf.find_functions(name);
            let die = dies.first().unwrap_or_else(|| panic!("{name} defined"));
            let external = die
                .get_attr(DwAt::External as u64)
                .unwrap_or_else(|| panic!("{name} should be external"));
            assert_eq!(external.form(), DwForm::FlagPresent as u64);
        }
        // static functions omit DW_AT_external entirely.
        for name in ["add_a", "sum_b"] {
            let dies = dwarf.find_functions(name);
            let die = dies.first().unwrap_or_else(|| panic!("{name} defined"));
            assert!(
                die.get_attr(DwAt::External as u64).is_none(),
                "{name} is static and should not be external"
            );
        }
    });
}

// --- Range lists --------------------------------------------------------------

#[test]
fn test_dwarf_compile_unit_ranges() {
    get_test_fixture().with(|dwarf| {
        for cu_index in 0..dwarf.compile_units().len() {
            let root = dwarf.root_of(cu_index).expect("CU root");
            // Each fixture CU describes its code extent via DW_AT_ranges, so
            // low_pc()/high_pc() exercise the .debug_ranges decoding path.
            let low = root
                .low_pc()
                .unwrap_or_else(|e| panic!("cu {cu_index} low_pc: {e:?}"));
            let high = root
                .high_pc()
                .unwrap_or_else(|e| panic!("cu {cu_index} high_pc: {e:?}"));
            assert!(low < high, "cu {cu_index}: low {low} should be < high {high}");
        }
    });
}

#[test]
fn test_dwarf_compile_unit_range_entry_counts() {
    get_test_fixture().with(|dwarf| {
        // With -ffunction-sections each defined function lands in its own text
        // section, so a CU's range list has one entry per defined function:
        // lib_a.c -> {add_a, compute_a, entry_a}, lib_b.c -> {sum_b, entry_b},
        // main.c -> {main}. Map each CU by source name so the assertion does not
        // depend on CU ordering.
        let mut counts: HashMap<String, usize> = HashMap::new();
        for cu_index in 0..dwarf.compile_units().len() {
            let root = dwarf.root_of(cu_index).expect("CU root");
            let name = root.name().expect("CU name");
            let ranges = root
                .get_attr(DwAt::Ranges as u64)
                .expect("CU has DW_AT_ranges")
                .as_range_list()
                .expect("DW_AT_ranges resolves to a range list");
            counts.insert(name, ranges.iter().count());
        }
        assert_eq!(counts["src/lib_a.c"], 3);
        assert_eq!(counts["src/lib_b.c"], 2);
        assert_eq!(counts["src/main.c"], 1);
    });
}

// --- Line table ---------------------------------------------------------------
//
// The facts asserted below are hand-derived from the fixture C sources
// (`tools/dwarf_fixture/src/*.c`) and cross-checked against an independent
// decoder (`readelf --debug-dump=decodedline`), never against our own parser:
//
//   lib_a.c  add_a {@56  compute_a {@61  entry_a {@78   (lines 56-85)
//   lib_b.c  sum_b {@35  entry_b  {@40                  (lines 35-47)
//   main.c   main  {@10                                 (lines 10-14)
//
// With -ffunction-sections each defined function is compiled into its own text
// section, so a CU's line program holds one sequence (one end_sequence row) per
// defined function.

/// CU index of the fixture translation unit whose root `DW_AT_name` is
/// `src/<file>`. CU order is not guaranteed, so callers look CUs up by name.
fn line_table_cu(dwarf: &Dwarf, file: &str) -> usize {
    let want = format!("src/{file}");
    (0..dwarf.compile_units().len())
        .find(|&i| dwarf.root_of(i).unwrap().name().as_deref() == Some(want.as_str()))
        .unwrap_or_else(|| panic!("fixture has a {want} compile unit"))
}

#[test]
fn test_dwarf_line_table_main() {
    get_test_fixture().with(|dwarf| {
        let cu_index = line_table_cu(dwarf, "main.c");
        let rows: Vec<_> = dwarf
            .lines(cu_index)
            .expect("main.c has a line program")
            .collect();
        assert!(rows.len() >= 2, "line program has body rows plus an end row");

        // The first row is main's opening line (main.c:10), attributed to main.c.
        let first = &rows[0];
        assert_eq!(first.line(), 10);
        let file = dwarf
            .line_table_file(cu_index, first.file_entry().expect("row has a file"))
            .expect("file index resolves to a file entry");
        assert_eq!(file.path().file_name().unwrap(), OsStr::new("main.c"));

        // Every non-terminal row maps to a line in main's body (10-14).
        for row in &rows[..rows.len() - 1] {
            assert!(!row.end_sequence(), "only the final row ends the sequence");
            assert!(
                (10..=14).contains(&row.line()),
                "row line {} outside main's body",
                row.line()
            );
        }

        // The program terminates with exactly one end_sequence row.
        assert!(rows.last().unwrap().end_sequence());
        assert_eq!(rows.iter().filter(|r| r.end_sequence()).count(), 1);
    });
}

#[test]
fn test_dwarf_line_table_one_sequence_per_function() {
    get_test_fixture().with(|dwarf| {
        // One end_sequence row per defined function (see the range-entry-count
        // test), and the program always ends on an end_sequence row.
        for (file, expected_sequences) in [("lib_a.c", 3), ("lib_b.c", 2), ("main.c", 1)] {
            let cu_index = line_table_cu(dwarf, file);
            let rows: Vec<_> = dwarf.lines(cu_index).expect("CU has a line program").collect();
            assert!(
                rows.last().expect("line program is non-empty").end_sequence(),
                "{file}: line program must end on an end_sequence row"
            );
            assert_eq!(
                rows.iter().filter(|r| r.end_sequence()).count(),
                expected_sequences,
                "{file}: one sequence per defined function"
            );
        }
    });
}

#[test]
fn test_dwarf_line_entry_at_function_opening_line() {
    get_test_fixture().with(|dwarf| {
        // Each function's entry address (DW_AT_low_pc) resolves to the row for
        // its opening `{` line in the source. This ties the function index to
        // the line table via get_line_entry_at_address.
        let opening_line: &[(&str, u64, &str)] = &[
            ("add_a", 56, "lib_a.c"),
            ("compute_a", 61, "lib_a.c"),
            ("entry_a", 78, "lib_a.c"),
            ("sum_b", 35, "lib_b.c"),
            ("entry_b", 40, "lib_b.c"),
            ("main", 10, "main.c"),
        ];
        for &(name, line, source) in opening_line {
            let dies = dwarf.find_functions(name);
            let low = dies.first().expect("function defined").low_pc().expect("low_pc");
            let entry = dwarf
                .get_line_entry_at_address(low)
                .unwrap_or_else(|| panic!("{name} low_pc maps to a line entry"));
            assert_eq!(entry.line(), line, "{name} opens at line {line}");
            assert!(!entry.end_sequence(), "{name}: entry row is not a sequence terminator");

            let cu_index = dwarf
                .compile_unit_containing_address(low)
                .expect("low_pc belongs to a CU");
            let file = dwarf
                .line_table_file(cu_index, entry.file_entry().expect("row has a file"))
                .expect("file index resolves");
            assert_eq!(file.path().file_name().unwrap(), OsStr::new(source));
        }
    });
}

#[test]
fn test_dwarf_line_table_rows_attributed_to_own_source() {
    get_test_fixture().with(|dwarf| {
        // Every non-terminal row in a CU names that CU's own .c file and lies
        // within the line span its function definitions occupy.
        for (file, bounds) in [("lib_a.c", 56..=85), ("lib_b.c", 35..=47), ("main.c", 10..=14)] {
            let cu_index = line_table_cu(dwarf, file);
            for row in dwarf.lines(cu_index).expect("CU has a line program") {
                if row.end_sequence() {
                    continue;
                }
                assert!(
                    bounds.contains(&row.line()),
                    "{file}: row line {} outside {bounds:?}",
                    row.line()
                );
                let entry = dwarf
                    .line_table_file(cu_index, row.file_entry().expect("row has a file"))
                    .expect("file index resolves");
                assert_eq!(entry.path().file_name().unwrap(), OsStr::new(file));
            }
        }
    });
}

#[test]
fn test_dwarf_line_table_contains_known_statement_lines() {
    get_test_fixture().with(|dwarf| {
        // Specific source lines that must produce at least one row: each
        // function's opening `{` line and a statement line inside its body.
        let expected: &[(&str, &[u64])] = &[
            ("lib_a.c", &[56, 57, 61, 74, 78, 84]),
            ("lib_b.c", &[35, 37, 40, 46]),
            ("main.c", &[10, 11, 12, 13]),
        ];
        for &(file, lines) in expected {
            let cu_index = line_table_cu(dwarf, file);
            let present: std::collections::HashSet<u64> = dwarf
                .lines(cu_index)
                .expect("CU has a line program")
                .filter(|r| !r.end_sequence())
                .map(|r| r.line())
                .collect();
            for &line in lines {
                assert!(present.contains(&line), "{file}: expected a row for line {line}");
            }
        }
    });
}

#[test]
fn test_dwarf_line_table_addresses_monotonic_within_sequence() {
    get_test_fixture().with(|dwarf| {
        // Rows advance by non-decreasing address within a sequence; an
        // end_sequence row closes the run and resets the expectation.
        for file in ["lib_a.c", "lib_b.c", "main.c"] {
            let cu_index = line_table_cu(dwarf, file);
            let mut prev: Option<u64> = None;
            for row in dwarf.lines(cu_index).expect("CU has a line program") {
                let addr = row.address().address as u64;
                if let Some(p) = prev {
                    assert!(addr >= p, "{file}: address {addr:#x} < previous {p:#x}");
                }
                prev = if row.end_sequence() { None } else { Some(addr) };
            }
        }
    });
}
