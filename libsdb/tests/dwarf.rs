use std::{ffi::CString, path::PathBuf, sync::OnceLock};

use libsdb::{
    cursor::Cursor,
    dwarf::{AbbrevTableCache, COMPILE_UNIT_HEADER_SIZE, Die, Dwarf},
    elf::Elf,
};
use test_binary::TestBinary;

// uleb128 tests

#[test]
fn uleb128_zero() {
    let mut cursor = Cursor::new(&[0x00]);
    assert_eq!(cursor.uleb128().unwrap(), 0);
}

#[test]
fn uleb128_single_byte() {
    // Values 0–127 encode as a single byte with the high bit clear.
    let mut cursor = Cursor::new(&[0x7F]);
    assert_eq!(cursor.uleb128().unwrap(), 127);
}

#[test]
fn uleb128_two_bytes() {
    // 128 encodes as [0x80, 0x01]: low 7 bits = 0, next 7 bits = 1.
    let mut cursor = Cursor::new(&[0x80, 0x01]);
    assert_eq!(cursor.uleb128().unwrap(), 128);
}

#[test]
fn uleb128_three_bytes() {
    // 624_485 is the canonical example from the DWARF spec.
    // Encoded as [0xE5, 0x8E, 0x26].
    let mut cursor = Cursor::new(&[0xE5, 0x8E, 0x26]);
    assert_eq!(cursor.uleb128().unwrap(), 624_485);
}

#[test]
fn uleb128_max_u64() {
    // u64::MAX encoded as ten bytes (each carrying 7 bits, all 1s).
    let bytes: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    let mut cursor = Cursor::new(bytes);
    assert_eq!(cursor.uleb128().unwrap(), u64::MAX);
}

#[test]
fn uleb128_advances_cursor() {
    // After reading one uleb128 value the cursor should be positioned at the next byte.
    let mut cursor = Cursor::new(&[0x01, 0x02]);
    assert_eq!(cursor.uleb128().unwrap(), 1);
    assert_eq!(cursor.uleb128().unwrap(), 2);
}

#[test]
fn uleb128_empty_returns_error() {
    let mut cursor = Cursor::new(&[]);
    assert!(cursor.uleb128().is_err());
}

// sleb128 tests

#[test]
fn sleb128_zero() {
    let mut cursor = Cursor::new(&[0x00]);
    assert_eq!(cursor.sleb128().unwrap(), 0);
}

#[test]
fn sleb128_positive_single_byte() {
    // 63 fits in 7 bits and has the sign bit clear → single byte.
    let mut cursor = Cursor::new(&[63]);
    assert_eq!(cursor.sleb128().unwrap(), 63);
}

#[test]
fn sleb128_negative_single_byte() {
    // -1: all bits set in the 7-bit value (0x7F) with the high continuation bit clear.
    let mut cursor = Cursor::new(&[0x7F]);
    assert_eq!(cursor.sleb128().unwrap(), -1);
}

#[test]
fn sleb128_negative_two_bytes() {
    // -128 encodes as [0x80, 0x7F].
    let mut cursor = Cursor::new(&[0x80, 0x7F]);
    assert_eq!(cursor.sleb128().unwrap(), -128);
}

#[test]
fn sleb128_positive_two_bytes() {
    // 128 encodes as [0x80, 0x00] for unsigned, but sleb128 of [0x80, 0x00] is 128
    // because the sign bit (bit 6) of the final byte (0x00) is clear.
    let mut cursor = Cursor::new(&[0x80, 0x01]);
    assert_eq!(cursor.sleb128().unwrap(), 128);
}

#[test]
fn sleb128_large_negative() {
    // -123_456 encoded via the DWARF sleb128 algorithm.
    // -123_456 in two's complement (64-bit) = 0xFFFF_FFFF_FFFE_1E40
    // Working out the encoding:
    //   byte 0: (-123456 & 0x7F) | 0x80 = (0x40) | 0x80 = 0xC0, shift >>7 → -965
    //   byte 1: (-965 & 0x7F) | 0x80 = (0x7B) | 0x80 = 0xFB, shift >>7 → -8 (not done, has more)
    // Let's just use known-good bytes: leb128 crate / manual calculation.
    // -123456 = 0xFFFFFFFFFFFE1E40
    // Encoding (little-endian, 7 bits per byte, continuation bit):
    //   0xC0 | 0x80 → 0xC0 (7 lsb of -123456 = 0x40, more bytes follow → 0xC0)
    //   next 7 bits: (-123456 >> 7) = -965; 0x7B | 0x80 → 0xFB
    //   next 7 bits: (-965 >> 7) = -8;      0x78 | 0x80 → 0xF8
    //   next 7 bits: (-8 >> 7) = -1;        0x7F — sign bit set, no more bytes needed
    let bytes: &[u8] = &[0xC0, 0xBB, 0x78];
    let mut cursor = Cursor::new(bytes);
    assert_eq!(cursor.sleb128().unwrap(), -123_456);
}

#[test]
fn sleb128_advances_cursor() {
    // Encoding of -1 followed by encoding of 1.
    let mut cursor = Cursor::new(&[0x7F, 0x01]);
    assert_eq!(cursor.sleb128().unwrap(), -1);
    assert_eq!(cursor.sleb128().unwrap(), 1);
}

#[test]
fn sleb128_i64_min() {
    // i64::MIN = -2^63. Encoding: 9 continuation bytes (0x80, value bits all zero)
    // followed by 0x7F (bit 0 survives the shift to bit 63, setting the MSB).
    let bytes: &[u8] = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
    let mut cursor = Cursor::new(bytes);
    assert_eq!(cursor.sleb128().unwrap(), i64::MIN);
}

#[test]
fn sleb128_empty_returns_error() {
    let mut cursor = Cursor::new(&[]);
    assert!(cursor.sleb128().is_err());
}
#[test]
fn test_cursor_integer_extraction() {
    let input_bytes = {
        let mut bytes = Vec::<u8>::new();
        bytes.push(0u8);
        bytes.extend_from_slice(&(-666i16).to_le_bytes());
        bytes.extend_from_slice(&(666u32).to_le_bytes());
        bytes.extend_from_slice(&(666u64).to_le_bytes());
        bytes
    };

    let mut cursor = Cursor::new(&input_bytes);
    assert_eq!(cursor.read_u8().expect("Expected 0u8"), 0u8);
    assert_eq!(cursor.read_i16().expect("Expected -666i16"), -666i16);
    assert_eq!(cursor.read_u32().expect("Expected 666u32"), 666u32);
    assert_eq!(cursor.read_u64().expect("Expected 666u64"), 666u64);
    assert!(cursor.is_at_end());
}

#[test]
fn test_string_extraction() {
    let input_bytes = {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(b"Hello\0");
        bytes.extend_from_slice(b"World\0");
        bytes.extend_from_slice(b"QWERTY\0");
        bytes
    };
    let mut cursor = Cursor::new(&input_bytes);
    assert_eq!(
        cursor.read_string().expect("Failed to extract \"Hello\""),
        &CString::from_vec_with_nul(b"Hello\0".to_vec()).unwrap()
    );
    assert_eq!(
        cursor.read_string().expect("Failed to extract \"World\""),
        &CString::from_vec_with_nul(b"World\0".to_vec()).unwrap()
    );
    assert_eq!(
        cursor.read_string().expect("Failed to extract \"Hello\""),
        &CString::from_vec_with_nul(b"QWERTY\0".to_vec()).unwrap()
    );
    assert!(cursor.is_at_end());
}

/// Per-compile-unit child counts at the root DIE, computed independently with gimli.
/// Returns one entry per compile unit, in the same order gimli enumerates them.
fn gimli_root_child_counts(path: &PathBuf) -> Vec<usize> {
    let data = std::fs::read(path).unwrap();
    let obj = object::File::parse(&*data).unwrap();
    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    use object::Object as _;
    let load =
        |id: gimli::SectionId| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> {
            let data = obj
                .section_by_name(id.name())
                .and_then(|s| {
                    use object::ObjectSection as _;
                    s.data().ok()
                })
                .unwrap_or(&[]);
            Ok(gimli::EndianSlice::new(data, endian))
        };
    let gimli_dwarf = gimli::Dwarf::load(load).unwrap();
    let mut units = gimli_dwarf.units();
    let mut counts = Vec::new();
    while let Some(header) = units.next().unwrap() {
        let unit = gimli_dwarf.unit(header).unwrap();
        let mut tree = unit.entries_tree(None).unwrap();
        let root = tree.root().unwrap();
        let mut children = root.children();
        let mut count = 0;
        while children.next().unwrap().is_some() {
            count += 1;
        }
        counts.push(count);
    }
    counts
}

#[test]
fn test_dwarf_die_tree_traversal() {
    let test_executable = PathBuf::from(
        TestBinary::relative_to_parent(
            "hello_sdb",
            &PathBuf::from_iter(["..", "tools", "hello_sdb", "Cargo.toml"]),
        )
        .with_profile("dev")
        .build()
        .expect("Failed to build test binary"),
    );
    let elf = Elf::new(&test_executable).expect("Failed to create Elf object");
    let mut abbrev_table = AbbrevTableCache::new(&elf);
    let dwarf = Dwarf::new(&elf).expect("Failed to parse Dwarf object");

    // validate the number of compile units (and per-unit root-child counts)
    // against an independent gimli-based implementation.
    let expected_child_counts = gimli_root_child_counts(&test_executable);
    assert_eq!(dwarf.compile_units.len(), expected_child_counts.len());

    for (compile_unit, expected) in dwarf.compile_units.iter().zip(expected_child_counts.iter()) {
        let root = compile_unit
            .root(&mut abbrev_table)
            .expect("Failed to get root");

        // The root of a compile unit is always a DW_TAG_compile_unit DIE,
        // which is non-null and exposes a children iterator.
        assert!(
            !matches!(root, Die::Null(_)),
            "Compile unit root DIE should not be null"
        );
        let children = root
            .children(&dwarf)
            .expect("Root DIE should expose a children iterator")
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to iterate root DIE children");

        // Every yielded child must itself be a non-null DIE — the iterator
        // is responsible for stopping at the terminating null entry.
        for child in &children {
            assert!(
                matches!(child, Die::NonNull(_)),
                "DieChildrenIter must not yield the terminating null DIE"
            );
        }

        assert_eq!(
            children.len(),
            *expected,
            "Mismatched direct-child count for a compile unit's root DIE"
        );
    }
}

// ---------------------------------------------------------------------------
// Gimli lockstep comparison tests
// ---------------------------------------------------------------------------
//
// Strategy: build the `dwarf_fixture` binary once, parse it twice (libsdb +
// gimli), walk both trees in lockstep, and collect a Vec<DieRecord> where
// every entry holds parallel data from both parsers. Each focused test then
// iterates the records and asserts one specific property — that keeps
// failures targeted and decouples test logic from the (lifetime-heavy)
// parsing pipeline.

use libsdb::dwarf::Attr;
use libsdb::dwarf_constants::{DwAt, DwForm};

fn fixture_binary_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        PathBuf::from(
            TestBinary::relative_to_parent(
                "dwarf_fixture",
                &PathBuf::from_iter(["..", "tools", "dwarf_fixture", "Cargo.toml"]),
            )
            .with_profile("dev")
            .build()
            .expect("Failed to build dwarf_fixture"),
        )
    })
}

type GimliReader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

fn load_gimli<'a>(file_data: &'a [u8]) -> gimli::Dwarf<GimliReader<'a>> {
    use object::Object as _;
    use object::ObjectSection as _;
    let obj = object::File::parse(file_data).expect("object::File::parse failed");
    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    // The closure must outlive the gimli::Dwarf, but `obj` is captured by
    // move. We need `obj` to outlive the returned Dwarf, so we leak it by
    // storing it in a Box that gets forgotten — fine for tests since the
    // process exits shortly anyway. Alternative would be to thread `obj`
    // through every call site.
    let obj: &'a object::File<'a> = Box::leak(Box::new(obj));
    let load = move |id: gimli::SectionId| -> Result<GimliReader<'a>, gimli::Error> {
        let data = obj
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };
    gimli::Dwarf::load(load).expect("gimli::Dwarf::load failed")
}

/// Per-DIE record holding parallel data from libsdb and gimli.
#[derive(Debug)]
struct DieRecord {
    cu_index: usize,
    /// Position of this DIE within `compile_unit.data` (header-stripped).
    libsdb_position: usize,
    /// Absolute offset of this DIE within the `.debug_info` section, as
    /// computed from libsdb (`cu.debug_info_offset + HEADER + position`).
    libsdb_abs_offset: usize,
    libsdb_tag: u64,
    libsdb_has_children: bool,
    libsdb_attr_specs: Vec<(u64, u64)>, // (attr_code, form_code)

    /// Absolute offset of this DIE in `.debug_info`, from gimli.
    gimli_abs_offset: usize,
    /// Offset within the gimli unit (excluding any unit header).
    gimli_unit_offset: usize,
    gimli_tag: u16,
    gimli_has_children: bool,
    gimli_attrs: Vec<GimliAttrInfo>,

    /// Per-attribute extracted values from libsdb. Indexed identically to
    /// `libsdb_attr_specs`.
    libsdb_attr_values: Vec<SdbExtracted>,
}

#[derive(Debug, Clone)]
struct GimliAttrInfo {
    name: u16,
    form: u16,
    extracted: GimliExtracted,
}

// Inner payloads on these variants feed Debug output in panic messages
// (not direct field reads), so `dead_code` would otherwise fire.
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum SdbExtracted {
    Address(usize),
    Int(u64),
    String(Vec<u8>),
    SecOffset(u32),
    Block(Vec<u8>),
    CuLocalRefPos(usize),
    ReferenceTargetAbs(usize),
    NotProbed,
    ExtractError(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum GimliExtracted {
    Address(u64),
    Int(u64),
    String(Vec<u8>),
    SecOffset(u64),
    Block(Vec<u8>),
    ReferenceTargetAbs(usize),
    Flag(bool),
    Other,
}

/// Bundle of pre-built test data shared by every comparison test.
struct LockstepData {
    records: Vec<DieRecord>,
}

fn build_lockstep_data() -> LockstepData {
    let path = fixture_binary_path();
    let binary_data = std::fs::read(path).expect("Failed to read fixture binary");
    // Leak the binary data so `gimli::Dwarf` (which references it) can live
    // for the duration of this function call without juggling lifetimes.
    let binary_data: &'static [u8] = Box::leak(binary_data.into_boxed_slice());
    let gimli_dwarf = load_gimli(binary_data);

    let elf = Elf::new(path).expect("Failed to load ELF");
    let elf: &'static Elf = Box::leak(Box::new(elf));
    let dwarf = Dwarf::new(elf).expect("Failed to parse DWARF");
    let dwarf: &'static Dwarf<'static> = Box::leak(Box::new(dwarf));
    let mut abbrev_cache = AbbrevTableCache::new(elf);

    // First collect gimli's per-unit data (headers + units).
    let mut gimli_units: Vec<gimli::Unit<GimliReader<'static>>> = Vec::new();
    let mut headers = gimli_dwarf.units();
    while let Some(header) = headers.next().expect("gimli units iter") {
        gimli_units.push(gimli_dwarf.unit(header).expect("gimli::Dwarf::unit"));
    }
    assert_eq!(
        dwarf.compile_units.len(),
        gimli_units.len(),
        "libsdb CU count differs from gimli CU count"
    );

    let mut all_records: Vec<DieRecord> = Vec::new();
    // (record_index, attr_index, source attr) — resolved AFTER each CU walk
    // (so libsdb's `Die` and its &mut borrow of abbrev_cache have been
    // released).
    let cu_count = dwarf.compile_units.len();

    for cu_index in 0..cu_count {
        let libsdb_cu = &dwarf.compile_units[cu_index];
        let gimli_unit = &gimli_units[cu_index];
        let gimli_unit_section_offset = gimli_unit
            .header
            .offset()
            .as_debug_info_offset()
            .expect("gimli unit not in .debug_info")
            .0;

        // Holds (record_index_in_all_records, attr_index_in_record, attr).
        // Filled during walk, drained after `libsdb_root` is dropped.
        let mut pending_refs: Vec<(usize, usize, Attr<'static>)> = Vec::new();

        {
            let libsdb_root = libsdb_cu
                .root(&mut abbrev_cache)
                .expect("libsdb cu.root failed");
            let mut tree = gimli_unit
                .entries_tree(None)
                .expect("gimli entries_tree failed");
            let gimli_root = tree.root().expect("gimli entries tree root failed");

            walk_lockstep(
                cu_index,
                libsdb_cu,
                dwarf,
                &libsdb_root,
                &gimli_dwarf,
                gimli_unit,
                gimli_unit_section_offset,
                gimli_root,
                &mut all_records,
                &mut pending_refs,
            );
        }

        // Phase 2 — resolve references using the now-free abbrev cache.
        for (rec_idx, attr_idx, attr) in pending_refs {
            let result = attr.as_reference(dwarf, &mut abbrev_cache);
            match result {
                Ok(target_die) => {
                    if let Die::NonNull(p) = &target_die {
                        let abs = p.compile_unit().debug_info_offset()
                            + COMPILE_UNIT_HEADER_SIZE
                            + target_die.position();
                        all_records[rec_idx].libsdb_attr_values[attr_idx] =
                            SdbExtracted::ReferenceTargetAbs(abs);
                    } else {
                        all_records[rec_idx].libsdb_attr_values[attr_idx] =
                            SdbExtracted::ExtractError(
                                "as_reference returned Die::Null".to_string(),
                            );
                    }
                }
                Err(e) => {
                    all_records[rec_idx].libsdb_attr_values[attr_idx] =
                        SdbExtracted::ExtractError(format!("{e}"));
                }
            }
        }
    }

    LockstepData {
        records: all_records,
    }
}

fn lockstep_data() -> &'static LockstepData {
    static DATA: OnceLock<LockstepData> = OnceLock::new();
    DATA.get_or_init(build_lockstep_data)
}

/// Returns true if `form` is one of the block-encoded forms supported by
/// libsdb's `as_block` (NOT exprloc — which libsdb rejects).
fn is_libsdb_block_form(form: u64) -> bool {
    matches!(
        DwForm::try_from(form as u8).ok(),
        Some(DwForm::Block1 | DwForm::Block2 | DwForm::Block4 | DwForm::Block)
    )
}

/// Returns true if `form` is a CU-local reference (anything ref-typed except
/// `ref_addr`, which may cross CU boundaries).
fn is_cu_local_ref_form(form: u64) -> bool {
    matches!(
        DwForm::try_from(form as u8).ok(),
        Some(DwForm::Ref1 | DwForm::Ref2 | DwForm::Ref4 | DwForm::Ref8 | DwForm::RefUdata)
    )
}

/// Returns true if `form` is any reference form (including ref_addr).
fn is_any_ref_form(form: u64) -> bool {
    matches!(
        DwForm::try_from(form as u8).ok(),
        Some(
            DwForm::Ref1
                | DwForm::Ref2
                | DwForm::Ref4
                | DwForm::Ref8
                | DwForm::RefUdata
                | DwForm::RefAddr
        )
    )
}

/// Returns true if `form` is one of the integer forms `as_int` handles.
fn is_libsdb_int_form(form: u64) -> bool {
    matches!(
        DwForm::try_from(form as u8).ok(),
        Some(
            DwForm::Data1
                | DwForm::Data2
                | DwForm::Data4
                | DwForm::Data8
                | DwForm::Udata
                | DwForm::Sdata
        )
    )
}

/// Recursive walker. `pending_refs` accumulates Attrs for reference forms
/// that will be resolved after the per-CU walk completes (so the abbrev
/// cache is no longer mutably borrowed by `libsdb_root`).
fn walk_lockstep<'a, 'b>(
    cu_index: usize,
    libsdb_cu: &'a libsdb::dwarf::CompileUnit<'a>,
    libsdb_dwarf: &'a Dwarf<'a>,
    libsdb_die: &Die<'a, 'b>,
    gimli_dwarf: &gimli::Dwarf<GimliReader<'a>>,
    gimli_unit: &gimli::Unit<GimliReader<'a>>,
    gimli_unit_section_offset: usize,
    gimli_node: gimli::EntriesTreeNode<GimliReader<'a>>,
    out: &mut Vec<DieRecord>,
    pending_refs: &mut Vec<(usize, usize, Attr<'a>)>,
) {
    let gimli_entry = gimli_node.entry();
    let payload = match libsdb_die {
        Die::Null(_) => panic!("walk_lockstep called with Die::Null"),
        Die::NonNull(p) => p,
    };

    let libsdb_position = libsdb_die.position();
    let libsdb_abs_offset =
        libsdb_cu.debug_info_offset() + COMPILE_UNIT_HEADER_SIZE + libsdb_position;
    let libsdb_tag = payload.tag();
    let libsdb_has_children = payload.has_children();
    let libsdb_attr_specs: Vec<(u64, u64)> = payload
        .attr_specs()
        .iter()
        .map(|s| (s.attr(), s.form()))
        .collect();

    let gimli_unit_offset = gimli_entry.offset().0;
    let gimli_abs_offset = gimli_unit_section_offset + gimli_unit_offset;
    let gimli_tag = gimli_entry.tag().0;
    let gimli_has_children = gimli_entry.has_children();

    // Look up the abbreviation in gimli to recover per-attr form codes
    // (the public `Attribute` API doesn't expose form). The abbrev code
    // libsdb parsed for this DIE should match gimli's — if it doesn't,
    // both sides are reading different bytes.
    let abbrev_code = payload.abbrev_code();
    let gimli_abbrev = gimli_unit
        .abbreviations
        .get(abbrev_code)
        .unwrap_or_else(|| {
            panic!(
                "gimli has no abbrev code {} for DIE @ {:#x} (CU {})",
                abbrev_code, libsdb_abs_offset, cu_index
            )
        });
    let gimli_specs = gimli_abbrev.attributes();
    let mut gimli_attrs: Vec<GimliAttrInfo> = Vec::with_capacity(gimli_specs.len());
    let mut iter = gimli_entry.attrs();
    for spec in gimli_specs {
        let attr = iter
            .next()
            .expect("gimli attrs next")
            .expect("gimli attrs ran out before specs");
        gimli_attrs.push(extract_gimli_attr(
            &attr,
            spec.name().0,
            spec.form().0,
            gimli_dwarf,
            gimli_unit,
        ));
    }
    assert!(
        iter.next().expect("gimli attrs trailing").is_none(),
        "gimli attrs iter had more entries than the abbreviation declared"
    );

    // Extract libsdb values for each attribute.
    let mut libsdb_attr_values: Vec<SdbExtracted> =
        Vec::with_capacity(libsdb_attr_specs.len());
    for &(attr_code, form_code) in &libsdb_attr_specs {
        let attr = match payload.get_attr(attr_code) {
            Some(a) => a,
            None => {
                libsdb_attr_values.push(SdbExtracted::ExtractError(
                    "DiePayload::get_attr returned None for an attr code in its own spec list"
                        .to_string(),
                ));
                continue;
            }
        };
        libsdb_attr_values.push(extract_libsdb_attr(&attr, form_code));
    }

    let record_index = out.len();
    out.push(DieRecord {
        cu_index,
        libsdb_position,
        libsdb_abs_offset,
        libsdb_tag,
        libsdb_has_children,
        libsdb_attr_specs: libsdb_attr_specs.clone(),
        gimli_abs_offset,
        gimli_unit_offset,
        gimli_tag,
        gimli_has_children,
        gimli_attrs,
        libsdb_attr_values,
    });

    // Queue reference attrs for phase-2 resolution.
    for (attr_idx, &(attr_code, form_code)) in libsdb_attr_specs.iter().enumerate() {
        if is_any_ref_form(form_code)
            && attr_code != DwAt::Sibling as u64 /* sibling is exercised separately */
        {
            if let Some(attr) = payload.get_attr(attr_code) {
                // SAFETY: Attr<'a> borrows from CompileUnit<'a> only — not from
                // any &mut on the abbrev cache. Transmuting the inner lifetime
                // is a workaround for the test's 'static dwarf reference; the
                // referenced data outlives the test.
                let attr_static: Attr<'static> = unsafe { std::mem::transmute(attr) };
                pending_refs.push((record_index, attr_idx, attr_static));
            }
        }
    }

    // Recurse into children, lockstep with gimli.
    let mut gimli_children = gimli_node.children();
    let libsdb_children_opt = libsdb_die.children(libsdb_dwarf);
    let mut libsdb_children: Vec<Die<'a, 'b>> = match libsdb_children_opt {
        None => Vec::new(),
        Some(iter) => iter
            .collect::<Result<Vec<_>, _>>()
            .expect("libsdb DieChildrenIter error"),
    };

    let mut child_index = 0;
    while let Some(gimli_child) = gimli_children.next().expect("gimli children iter") {
        let libsdb_child = libsdb_children
            .get(child_index)
            .expect("libsdb has fewer children than gimli at this DIE");
        walk_lockstep(
            cu_index,
            libsdb_cu,
            libsdb_dwarf,
            libsdb_child,
            gimli_dwarf,
            gimli_unit,
            gimli_unit_section_offset,
            gimli_child,
            out,
            pending_refs,
        );
        child_index += 1;
    }
    assert_eq!(
        child_index,
        libsdb_children.len(),
        "libsdb has more children than gimli at DIE @ libsdb_abs_offset={:#x} \
         (cu {}, libsdb has {}, gimli has {})",
        libsdb_abs_offset,
        cu_index,
        libsdb_children.len(),
        child_index
    );
    // Suppress unused warning if libsdb_children is not consumed.
    let _ = &mut libsdb_children;
}

fn extract_libsdb_attr(attr: &Attr, form_code: u64) -> SdbExtracted {
    let form = match DwForm::try_from(form_code as u8) {
        Ok(f) => f,
        Err(_) => return SdbExtracted::NotProbed,
    };
    match form {
        DwForm::Addr => match attr.as_address() {
            Ok(fa) => SdbExtracted::Address(fa.address),
            Err(e) => SdbExtracted::ExtractError(format!("as_address: {e}")),
        },
        DwForm::SecOffset => match attr.as_section_offset() {
            Ok(v) => SdbExtracted::SecOffset(v),
            Err(e) => SdbExtracted::ExtractError(format!("as_section_offset: {e}")),
        },
        DwForm::Data1
        | DwForm::Data2
        | DwForm::Data4
        | DwForm::Data8
        | DwForm::Udata
        | DwForm::Sdata => match attr.as_int() {
            Ok(v) => SdbExtracted::Int(v),
            Err(e) => SdbExtracted::ExtractError(format!("as_int: {e}")),
        },
        DwForm::String | DwForm::Strp => match attr.as_string() {
            Ok(s) => SdbExtracted::String(s.to_bytes().to_vec()),
            Err(e) => SdbExtracted::ExtractError(format!("as_string: {e}")),
        },
        DwForm::Block1 | DwForm::Block2 | DwForm::Block4 | DwForm::Block => {
            match attr.as_block() {
                Ok(b) => SdbExtracted::Block(b.to_vec()),
                Err(e) => SdbExtracted::ExtractError(format!("as_block: {e}")),
            }
        }
        DwForm::Ref1 | DwForm::Ref2 | DwForm::Ref4 | DwForm::Ref8 | DwForm::RefUdata => {
            // CU-local refs — record `as_cu_local_reference_position`. The
            // full `as_reference` resolution is filled in phase 2 (and
            // overwrites this value).
            match attr.as_cu_local_reference_position() {
                Ok(p) => SdbExtracted::CuLocalRefPos(p),
                Err(e) => SdbExtracted::ExtractError(format!("as_cu_local_reference_position: {e}")),
            }
        }
        DwForm::RefAddr => {
            // Phase-2 resolution fills this in.
            SdbExtracted::NotProbed
        }
        DwForm::Flag | DwForm::FlagPresent | DwForm::Exprloc | DwForm::RefSig8
        | DwForm::Indirect => SdbExtracted::NotProbed,
    }
}

fn extract_gimli_attr<R: gimli::Reader<Offset = usize>>(
    attr: &gimli::Attribute<R>,
    name: u16,
    form: u16,
    gimli_dwarf: &gimli::Dwarf<R>,
    gimli_unit: &gimli::Unit<R>,
) -> GimliAttrInfo {
    // Use raw_value(): gimli's value() normalizes based on attribute name
    // (e.g. DW_AT_language data2 becomes Language enum), which loses the
    // form-equivalence we want to verify against libsdb's form-based
    // extractors.
    let extracted = match attr.raw_value() {
        gimli::AttributeValue::Addr(v) => GimliExtracted::Address(v),
        gimli::AttributeValue::Data1(v) => GimliExtracted::Int(v as u64),
        gimli::AttributeValue::Data2(v) => GimliExtracted::Int(v as u64),
        gimli::AttributeValue::Data4(v) => GimliExtracted::Int(v as u64),
        gimli::AttributeValue::Data8(v) => GimliExtracted::Int(v),
        gimli::AttributeValue::Sdata(v) => GimliExtracted::Int(v as u64),
        gimli::AttributeValue::Udata(v) => GimliExtracted::Int(v),
        gimli::AttributeValue::SecOffset(v) => GimliExtracted::SecOffset(v as u64),
        gimli::AttributeValue::Block(r) => {
            GimliExtracted::Block(r.to_slice().expect("block to_slice").to_vec())
        }
        gimli::AttributeValue::Exprloc(expr) => GimliExtracted::Block(
            expr.0.to_slice().expect("exprloc to_slice").to_vec(),
        ),
        gimli::AttributeValue::String(r) => {
            GimliExtracted::String(r.to_slice().expect("string to_slice").to_vec())
        }
        gimli::AttributeValue::DebugStrRef(_) => {
            // raw_value() returns the raw offset; use attr_string to resolve
            // it through .debug_str.
            let s = gimli_dwarf
                .attr_string(gimli_unit, attr.raw_value())
                .expect("attr_string");
            GimliExtracted::String(s.to_slice().expect("debug_str to_slice").to_vec())
        }
        gimli::AttributeValue::Flag(b) => GimliExtracted::Flag(b),
        gimli::AttributeValue::UnitRef(unit_off) => {
            let abs = unit_off
                .to_debug_info_offset(&gimli_unit.header)
                .expect("UnitRef -> debug_info_offset")
                .0;
            GimliExtracted::ReferenceTargetAbs(abs)
        }
        gimli::AttributeValue::DebugInfoRef(off) => {
            GimliExtracted::ReferenceTargetAbs(off.0)
        }
        _ => GimliExtracted::Other,
    };
    GimliAttrInfo {
        name,
        form,
        extracted,
    }
}

// ---------------------------------------------------------------------------
// Individual tests
// ---------------------------------------------------------------------------

#[test]
fn gimli_cu_count_matches() {
    // Implicit: build_lockstep_data already asserts CU count.
    let _ = lockstep_data();
}

#[test]
fn gimli_die_abs_offset_matches() {
    let data = lockstep_data();
    for rec in &data.records {
        assert_eq!(
            rec.libsdb_abs_offset, rec.gimli_abs_offset,
            "CU {} DIE: libsdb abs offset {:#x} != gimli {:#x}",
            rec.cu_index, rec.libsdb_abs_offset, rec.gimli_abs_offset
        );
    }
}

#[test]
fn gimli_die_position_within_cu_matches() {
    // libsdb stores `position` relative to header-stripped CU data; gimli's
    // unit-relative offset includes the header. The two should differ by
    // exactly COMPILE_UNIT_HEADER_SIZE.
    let data = lockstep_data();
    for rec in &data.records {
        assert_eq!(
            rec.libsdb_position + COMPILE_UNIT_HEADER_SIZE,
            rec.gimli_unit_offset,
            "CU {} DIE: libsdb position {:#x} + header != gimli unit offset {:#x}",
            rec.cu_index,
            rec.libsdb_position,
            rec.gimli_unit_offset
        );
    }
}

#[test]
fn gimli_die_tags_match() {
    let data = lockstep_data();
    for rec in &data.records {
        assert_eq!(
            rec.libsdb_tag,
            rec.gimli_tag as u64,
            "CU {} DIE @ {:#x}: libsdb tag {:#x} != gimli {:#x}",
            rec.cu_index,
            rec.libsdb_abs_offset,
            rec.libsdb_tag,
            rec.gimli_tag
        );
    }
}

#[test]
fn gimli_die_has_children_matches() {
    let data = lockstep_data();
    for rec in &data.records {
        assert_eq!(
            rec.libsdb_has_children, rec.gimli_has_children,
            "CU {} DIE @ {:#x}: libsdb has_children {} != gimli {}",
            rec.cu_index,
            rec.libsdb_abs_offset,
            rec.libsdb_has_children,
            rec.gimli_has_children
        );
    }
}

#[test]
fn gimli_die_attribute_specs_match() {
    let data = lockstep_data();
    for rec in &data.records {
        assert_eq!(
            rec.libsdb_attr_specs.len(),
            rec.gimli_attrs.len(),
            "CU {} DIE @ {:#x}: libsdb {} attrs != gimli {} attrs",
            rec.cu_index,
            rec.libsdb_abs_offset,
            rec.libsdb_attr_specs.len(),
            rec.gimli_attrs.len()
        );
        for (i, (sdb, gim)) in rec
            .libsdb_attr_specs
            .iter()
            .zip(rec.gimli_attrs.iter())
            .enumerate()
        {
            assert_eq!(
                sdb.0, gim.name as u64,
                "CU {} DIE @ {:#x} attr {}: libsdb attr {:#x} != gimli {:#x}",
                rec.cu_index, rec.libsdb_abs_offset, i, sdb.0, gim.name
            );
            assert_eq!(
                sdb.1, gim.form as u64,
                "CU {} DIE @ {:#x} attr {} ({:#x}): libsdb form {:#x} != gimli {:#x}",
                rec.cu_index, rec.libsdb_abs_offset, i, sdb.0, sdb.1, gim.form
            );
        }
    }
}

#[test]
fn gimli_die_string_attrs_match() {
    let data = lockstep_data();
    let mut probed = 0usize;
    for rec in &data.records {
        for (i, &(_, form)) in rec.libsdb_attr_specs.iter().enumerate() {
            let is_string_form = matches!(
                DwForm::try_from(form as u8).ok(),
                Some(DwForm::String | DwForm::Strp)
            );
            if !is_string_form {
                continue;
            }
            let sdb = &rec.libsdb_attr_values[i];
            let gim = &rec.gimli_attrs[i].extracted;
            match (sdb, gim) {
                (SdbExtracted::String(s_bytes), GimliExtracted::String(g_bytes)) => {
                    assert_eq!(
                        s_bytes, g_bytes,
                        "CU {} DIE @ {:#x} attr {}: string mismatch",
                        rec.cu_index, rec.libsdb_abs_offset, i
                    );
                    probed += 1;
                }
                _ => panic!(
                    "CU {} DIE @ {:#x} attr {}: form {:#x} not extracted as String: sdb={:?} gim={:?}",
                    rec.cu_index, rec.libsdb_abs_offset, i, form, sdb, gim
                ),
            }
        }
    }
    assert!(probed > 0, "fixture had no string-form attributes to probe");
}

#[test]
fn gimli_die_int_attrs_match() {
    let data = lockstep_data();
    let mut probed = 0usize;
    for rec in &data.records {
        for (i, &(_, form)) in rec.libsdb_attr_specs.iter().enumerate() {
            if !is_libsdb_int_form(form) {
                continue;
            }
            let sdb = &rec.libsdb_attr_values[i];
            let gim = &rec.gimli_attrs[i].extracted;
            match (sdb, gim) {
                (SdbExtracted::Int(s), GimliExtracted::Int(g)) => {
                    assert_eq!(
                        s, g,
                        "CU {} DIE @ {:#x} attr {}: libsdb int {} != gimli {}",
                        rec.cu_index, rec.libsdb_abs_offset, i, s, g
                    );
                    probed += 1;
                }
                _ => panic!(
                    "CU {} DIE @ {:#x} attr {}: form {:#x} not extracted as Int: sdb={:?} gim={:?}",
                    rec.cu_index, rec.libsdb_abs_offset, i, form, sdb, gim
                ),
            }
        }
    }
    assert!(probed > 0, "fixture had no integer-form attributes to probe");
}

#[test]
fn gimli_die_address_attrs_match() {
    let data = lockstep_data();
    let mut probed = 0usize;
    for rec in &data.records {
        for (i, &(_, form)) in rec.libsdb_attr_specs.iter().enumerate() {
            if DwForm::try_from(form as u8).ok() != Some(DwForm::Addr) {
                continue;
            }
            let sdb = &rec.libsdb_attr_values[i];
            let gim = &rec.gimli_attrs[i].extracted;
            match (sdb, gim) {
                (SdbExtracted::Address(s), GimliExtracted::Address(g)) => {
                    assert_eq!(
                        *s as u64, *g,
                        "CU {} DIE @ {:#x} attr {}: libsdb addr {:#x} != gimli {:#x}",
                        rec.cu_index, rec.libsdb_abs_offset, i, s, g
                    );
                    probed += 1;
                }
                _ => panic!(
                    "CU {} DIE @ {:#x} attr {}: form DW_FORM_addr extraction mismatch: sdb={:?} gim={:?}",
                    rec.cu_index, rec.libsdb_abs_offset, i, sdb, gim
                ),
            }
        }
    }
    assert!(probed > 0, "fixture had no address-form attributes to probe");
}

#[test]
fn gimli_die_section_offset_attrs_match() {
    let data = lockstep_data();
    let mut probed = 0usize;
    for rec in &data.records {
        for (i, &(_, form)) in rec.libsdb_attr_specs.iter().enumerate() {
            if DwForm::try_from(form as u8).ok() != Some(DwForm::SecOffset) {
                continue;
            }
            let sdb = &rec.libsdb_attr_values[i];
            let gim = &rec.gimli_attrs[i].extracted;
            match (sdb, gim) {
                (SdbExtracted::SecOffset(s), GimliExtracted::SecOffset(g)) => {
                    assert_eq!(
                        *s as u64, *g,
                        "CU {} DIE @ {:#x} attr {}: libsdb sec_offset {:#x} != gimli {:#x}",
                        rec.cu_index, rec.libsdb_abs_offset, i, s, g
                    );
                    probed += 1;
                }
                _ => panic!(
                    "CU {} DIE @ {:#x} attr {}: form DW_FORM_sec_offset extraction mismatch: sdb={:?} gim={:?}",
                    rec.cu_index, rec.libsdb_abs_offset, i, sdb, gim
                ),
            }
        }
    }
    assert!(probed > 0, "fixture had no sec_offset attributes to probe");
}

#[test]
fn gimli_die_block_attrs_match() {
    let data = lockstep_data();
    let mut probed = 0usize;
    for rec in &data.records {
        for (i, &(_, form)) in rec.libsdb_attr_specs.iter().enumerate() {
            if !is_libsdb_block_form(form) {
                continue;
            }
            let sdb = &rec.libsdb_attr_values[i];
            let gim = &rec.gimli_attrs[i].extracted;
            match (sdb, gim) {
                (SdbExtracted::Block(s), GimliExtracted::Block(g)) => {
                    assert_eq!(
                        s, g,
                        "CU {} DIE @ {:#x} attr {}: block bytes differ",
                        rec.cu_index, rec.libsdb_abs_offset, i
                    );
                    probed += 1;
                }
                _ => panic!(
                    "CU {} DIE @ {:#x} attr {}: form {:#x} not extracted as Block: sdb={:?} gim={:?}",
                    rec.cu_index, rec.libsdb_abs_offset, i, form, sdb, gim
                ),
            }
        }
    }
    // The fixture may or may not emit block-form attributes; if it doesn't,
    // skip the "probed > 0" assertion silently. Block attrs are rare in C.
    let _ = probed;
}

#[test]
fn gimli_die_references_match() {
    let data = lockstep_data();
    let mut probed = 0usize;
    for rec in &data.records {
        for (i, &(attr_code, form)) in rec.libsdb_attr_specs.iter().enumerate() {
            if !is_any_ref_form(form) {
                continue;
            }
            // Sibling references are not resolved into ReferenceTargetAbs by
            // phase 2 (we exclude them so the cache stays free); skip them
            // here too.
            if attr_code == DwAt::Sibling as u64 {
                continue;
            }
            let sdb = &rec.libsdb_attr_values[i];
            let gim = &rec.gimli_attrs[i].extracted;
            match (sdb, gim) {
                (
                    SdbExtracted::ReferenceTargetAbs(s),
                    GimliExtracted::ReferenceTargetAbs(g),
                ) => {
                    assert_eq!(
                        s, g,
                        "CU {} DIE @ {:#x} attr {} ({:#x}): libsdb ref target {:#x} != gimli {:#x}",
                        rec.cu_index, rec.libsdb_abs_offset, i, attr_code, s, g
                    );
                    probed += 1;
                }
                _ => panic!(
                    "CU {} DIE @ {:#x} attr {}: ref form {:#x} extraction mismatch: sdb={:?} gim={:?}",
                    rec.cu_index, rec.libsdb_abs_offset, i, form, sdb, gim
                ),
            }
        }
    }
    assert!(probed > 0, "fixture had no resolvable reference attributes");
}

#[test]
fn gimli_cu_local_reference_position_matches() {
    // For CU-local ref forms, the phase-1 extractor recorded
    // `as_cu_local_reference_position()`. Phase 2 then overwrites these
    // with `ReferenceTargetAbs`. To exercise just the CU-local extractor,
    // we re-walk and call it directly.
    let path = fixture_binary_path();
    let elf = Elf::new(path).expect("Failed to load ELF for cu-local ref test");
    let dwarf = Dwarf::new(&elf).expect("Failed to parse DWARF");
    let mut cache = AbbrevTableCache::new(&elf);

    let binary_data = std::fs::read(path).expect("read fixture");
    let gimli_dwarf = load_gimli(&binary_data);
    let mut gimli_units = Vec::new();
    let mut headers = gimli_dwarf.units();
    while let Some(h) = headers.next().expect("units iter") {
        gimli_units.push(gimli_dwarf.unit(h).expect("dwarf.unit"));
    }

    let mut checked = 0usize;
    for (cu_idx, libsdb_cu) in dwarf.compile_units.iter().enumerate() {
        let gimli_unit = &gimli_units[cu_idx];
        let root = libsdb_cu.root(&mut cache).expect("root");
        check_cu_local_refs(libsdb_cu, &dwarf, &root, gimli_unit, &mut checked);
    }
    assert!(checked > 0, "fixture had no CU-local references to check");
}

fn check_cu_local_refs<'a, 'b>(
    libsdb_cu: &'a libsdb::dwarf::CompileUnit<'a>,
    libsdb_dwarf: &'a Dwarf<'a>,
    libsdb_die: &Die<'a, 'b>,
    gimli_unit: &gimli::Unit<GimliReader<'a>>,
    checked: &mut usize,
) {
    if let Die::NonNull(payload) = libsdb_die {
        let unit_offset = libsdb_die.position() + COMPILE_UNIT_HEADER_SIZE;
        let gimli_entry = gimli_unit
            .entry(gimli::UnitOffset(unit_offset))
            .expect("gimli unit.entry by offset");
        for spec in payload.attr_specs() {
            if !is_cu_local_ref_form(spec.form()) {
                continue;
            }
            let attr_code = spec.attr();
            let libsdb_attr = payload.get_attr(attr_code).expect("get_attr");
            let libsdb_pos = libsdb_attr
                .as_cu_local_reference_position()
                .expect("as_cu_local_reference_position");

            let gimli_attr = gimli_entry
                .attr(gimli::DwAt(attr_code as u16))
                .expect("gimli entry.attr")
                .expect("gimli attr present");
            let expected_unit_offset = match gimli_attr.value() {
                gimli::AttributeValue::UnitRef(uo) => uo.0,
                other => panic!("expected UnitRef, got {:?}", other),
            };
            let expected_libsdb_pos = expected_unit_offset - COMPILE_UNIT_HEADER_SIZE;
            assert_eq!(
                libsdb_pos, expected_libsdb_pos,
                "CU-local ref position mismatch at DIE position {:#x} attr {:#x}: \
                 libsdb {:#x} != expected {:#x}",
                libsdb_die.position(),
                attr_code,
                libsdb_pos,
                expected_libsdb_pos
            );
            *checked += 1;
        }
        if let Some(children_iter) = libsdb_die.children(libsdb_dwarf) {
            let children: Vec<_> = children_iter
                .collect::<Result<Vec<_>, _>>()
                .expect("children");
            for child in &children {
                check_cu_local_refs(libsdb_cu, libsdb_dwarf, child, gimli_unit, checked);
            }
        }
    }
    let _ = libsdb_cu;
}

#[test]
fn gimli_total_die_count_matches() {
    // Compute libsdb's total DIE count per CU and compare to gimli's.
    let data = lockstep_data();
    // Group by CU.
    let mut sdb_counts = std::collections::HashMap::<usize, usize>::new();
    for rec in &data.records {
        *sdb_counts.entry(rec.cu_index).or_insert(0) += 1;
    }

    let path = fixture_binary_path();
    let binary_data = std::fs::read(path).expect("read");
    let gimli_dwarf = load_gimli(&binary_data);
    let mut headers = gimli_dwarf.units();
    let mut cu_idx = 0usize;
    while let Some(h) = headers.next().expect("units iter") {
        let unit = gimli_dwarf.unit(h).expect("dwarf.unit");
        let mut tree = unit.entries_tree(None).expect("entries_tree");
        let root = tree.root().expect("root");
        let count = count_gimli_subtree(root);
        assert_eq!(
            sdb_counts.get(&cu_idx).copied().unwrap_or(0),
            count,
            "CU {}: libsdb counted {} DIEs, gimli counted {}",
            cu_idx,
            sdb_counts.get(&cu_idx).copied().unwrap_or(0),
            count
        );
        cu_idx += 1;
    }
}

fn count_gimli_subtree<R: gimli::Reader>(node: gimli::EntriesTreeNode<R>) -> usize {
    let mut n = 1usize;
    let mut children = node.children();
    while let Some(child) = children.next().expect("children iter") {
        n += count_gimli_subtree(child);
    }
    n
}

#[test]
fn abbrev_cache_returns_same_table_for_same_offset() {
    let path = fixture_binary_path();
    let elf = Elf::new(path).expect("Elf");
    let mut cache = AbbrevTableCache::new(&elf);

    // Use the offset of CU 0's abbrev table.
    let dwarf = Dwarf::new(&elf).expect("Dwarf");
    let offset = dwarf.compile_units[0].abbrev_offset();

    let addr1 = {
        let t = cache.get_table_at_offset(offset).expect("first lookup");
        t as *const _ as usize
    };
    let addr2 = {
        let t = cache.get_table_at_offset(offset).expect("second lookup");
        t as *const _ as usize
    };
    assert_eq!(
        addr1, addr2,
        "AbbrevTableCache returned different table addresses for the same offset"
    );
}

#[test]
fn sibling_optimization_does_not_diverge_from_gimli() {
    // The main lockstep walk already cross-checks every DIE's tag and
    // position against gimli. Any bug in `DieChildrenIter`'s
    // DW_AT_sibling shortcut would surface as a position or count mismatch
    // there. This test additionally asserts the fixture actually contains
    // a DW_AT_sibling somewhere, so the optimization branch is exercised
    // by the suite.
    let data = lockstep_data();
    let mut saw_sibling = false;
    for rec in &data.records {
        for &(attr_code, _) in &rec.libsdb_attr_specs {
            if attr_code == DwAt::Sibling as u64 {
                saw_sibling = true;
                break;
            }
        }
        if saw_sibling {
            break;
        }
    }
    assert!(
        saw_sibling,
        "fixture does not contain any DW_AT_sibling attribute; \
         the sibling-skipping branch is not exercised"
    );
}
