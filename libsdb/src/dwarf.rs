use crate::dwarf_constants::{DwAt, DwForm};
use crate::elf::Elf;
use crate::{address::FileAddress, cursor::Cursor};
use anyhow::{Context, Result, anyhow};
use std::cell::RefCell;
use std::{collections::HashMap, ffi::CStr};

/// Size of the DWARF v4 compile unit header in DWARF32 format:
/// unit_length (4) + version (2) + debug_abbrev_offset (4) + address_size (1).
pub const COMPILE_UNIT_HEADER_SIZE: usize = 11;

// --- Top-level DWARF handle
pub struct Dwarf<'elf> {
    pub compile_units: Vec<CompileUnit<'elf>>,
    function_index: HashMap<String, Vec<IndexEntry<'elf>>>,
    abbrev_table_cache: RefCell<AbbrevTableCache<'elf>>,
}

pub struct CompileUnit<'elf> {
    abbrev_offset: usize,
    /// Start offset of this CU (including its header) within the .debug_info section.
    /// Used to resolve `DW_FORM_ref_addr` references that point into other CUs.
    debug_info_offset: usize,
    /// DIE bytes for this CU, with the [`COMPILE_UNIT_HEADER_SIZE`]-byte header
    /// already stripped. All offsets stored in this module (DIE `position`/`next`,
    /// `attr_locations`) are indices into this slice.
    data: &'elf [u8],
    elf: &'elf Elf,
}

struct IndexEntry<'elf> {
    compile_unit: &'elf CompileUnit<'elf>,
    offset: usize,
}

// --- Debugging Information Entries
pub enum Die<'elf, 'dwarf>
where
    'elf: 'dwarf,
{
    Null(
        usize, /* Offset of the start of this DIE within `compile_unit.data` */
    ),
    NonNull(DiePayload<'elf, 'dwarf>),
}

pub struct DiePayload<'elf, 'dwarf>
where
    'elf: 'dwarf,
{
    /// Offset of the start of this DIE within `compile_unit.data`.
    position: usize,
    /// Offset (within `compile_unit.data`) of either the next sibling or the
    /// first child of this DIE.
    next: usize,
    /// The compile unit that owns this Die
    compile_unit: &'dwarf CompileUnit<'elf>,
    /// abbrev entry for this DIE
    abbrev: &'dwarf Abbrev,
    /// Offsets within `compile_unit.data` where each attribute's value bytes live.
    attr_locations: Vec<usize>,
    /// Abbrev table
    abbrev_table: &'dwarf AbbrevTable,
}

pub struct DieChildrenIter<'elf, 'dwarf>
where
    'elf: 'dwarf,
{
    compile_unit: &'dwarf CompileUnit<'elf>,
    abbrev_table: &'dwarf AbbrevTable,
    current_offset: usize,
    done: bool,
}

// --- Attributes

pub struct Attr<'elf, 'dwarf>
where
    'elf: 'dwarf,
{
    form: u64,
    attr_type: u64,
    compile_unit: &'dwarf CompileUnit<'elf>,
    location_offset: usize, // Offset in compile_unit.data
    abbrev_table: &'dwarf AbbrevTable,
}

pub struct AttrSpec {
    attr: u64,
    form: u64,
}

// --- Abbreviations
pub struct Abbrev {
    code: u64,
    tag: u64,
    has_children: bool,
    attr_specs: Vec<AttrSpec>,
}

/// The .debug_abbrev section contains several abbreviation tables. Each compile
/// unit in the .debug_info section uses exactly one abbreviation table, but different
/// compile units may share the same table.
/// Maps byte offsets to another map, of integers to abbreviation entries.
pub type AbbrevTable = HashMap<u64 /* abbreviation code*/, Abbrev>;
pub struct AbbrevTableCache<'a> {
    elf: &'a Elf,
    tables: HashMap<usize /*offset into the .debug_abbrev section*/, AbbrevTable>,
}

// --- Range list related types

pub struct RangeList<'elf, 'dwarf>
where
    'elf: 'dwarf,
{
    compile_unit: &'dwarf CompileUnit<'elf>,
    data: &'elf [u8],
    base_address: FileAddress<'elf>,
}

pub struct RangeListEntry<'elf> {
    low: FileAddress<'elf>,
    high: FileAddress<'elf>,
}

pub struct RangeListIterator<'elf, 'dwarf>
where
    'elf: 'dwarf,
{
    compile_unit: &'dwarf CompileUnit<'elf>,
    data: &'elf [u8],
    position: usize,
    base_address: FileAddress<'elf>,
}

// ===================================================================

// --- Dwarf ---

impl<'elf> Dwarf<'elf> {
    pub fn new(elf: &'elf Elf) -> Result<Dwarf<'elf>> {
        let compile_units = parse_compile_units(elf)?;
        Ok(Dwarf {
            compile_units,
            function_index: HashMap::new(),
            abbrev_table_cache: RefCell::new(AbbrevTableCache {
                elf,
                tables: HashMap::new(),
            }),
        })
    }

    pub fn compile_unit_containing_address<'slf, 'b>(
        &'slf self,
        address: FileAddress<'elf>,
        abbrev_table: &'b AbbrevTable,
    ) -> Option<&'slf CompileUnit<'elf>> {
        self.compile_units.iter().find(|&compile_unit| {
            if compile_unit
                .root_internal(abbrev_table)
                .expect("Failed to extract root DIE from compile unit")
                .contains(address)
            {
                return true;
            }
            return false;
        })
    }

    pub fn function_containing_address<'b>(
        &mut self,
        address: FileAddress<'elf>,
        abbrev_table: &'b AbbrevTable,
    ) -> Option<Die<'elf, 'b>> {
        self.index();

        // (func1, [index_entry1, index_entry2]), (func2, [index_entry1]), ...
        // (func1, index_entry1), (func1, index_entry2), (func2, index_entry1)...
        for (_function_name, index_entry) in
            self.function_index
                .iter()
                .flat_map(|(function_name, index_entries)| {
                    index_entries
                        .iter()
                        .map(move |index_entry| (function_name, index_entry))
                })
        {
            let mut cursor = Cursor::new(&index_entry.compile_unit.data[index_entry.offset..]);
            let die = parse_die_raw(&mut cursor, index_entry.compile_unit, abbrev_table)
                .expect("Failed to parse DIE");
            match (die.contains(address), &die) {
                (true, Die::NonNull(die_payload)) => {
                    if die_payload.abbrev.tag == crate::dwarf_constants::DwTag::Subprogram as u64 {
                        return Some(die);
                    }
                }
                _ => {}
            }
        }
        return None;
    }

    pub fn find_functions<'b>(
        &mut self,
        function_name: &str,
        abbrev_table: &'b AbbrevTable,
    ) -> Vec<Die<'elf, 'b>> {
        self.index();
        let index_entries = match self.function_index.get(function_name) {
            Some(index_entries) => index_entries,
            None => return Vec::new(),
        };

        index_entries
            .iter()
            .map(|index_entry| {
                let mut cursor = Cursor::new(&index_entry.compile_unit.data[index_entry.offset..]);
                parse_die_raw(&mut cursor, index_entry.compile_unit, abbrev_table)
                    .expect("Failed to parse DIE")
            })
            .collect()
    }

    fn index<'b>(&mut self) {
        todo!()
    }

    fn index_die<'b>(&mut self, die: Die<'elf, 'b>) {
        todo!()
    }
}

fn find_cu_containing<'a, 'elf>(
    dwarf: &'a Dwarf<'elf>,
    abs_offset: usize,
) -> Result<(
    &'a CompileUnit<'elf>,
    usize, /*Offset relative to the found CU */
)> {
    let cu = dwarf
        .compile_units
        .iter()
        .find(|cu| {
            // `data` no longer includes the CU header, so the CU's footprint
            // in .debug_info is `[debug_info_offset, debug_info_offset + header + data)`.
            abs_offset >= cu.debug_info_offset
                && abs_offset < cu.debug_info_offset + COMPILE_UNIT_HEADER_SIZE + cu.data.len()
        })
        .ok_or_else(|| anyhow!("RefAddr {:#x} not in any compile unit", abs_offset))?;
    Ok((cu, abs_offset - cu.debug_info_offset))
}

fn parse_compile_units<'elf>(elf: &'elf Elf) -> Result<Vec<CompileUnit<'elf>>> {
    let debug_info_data = elf
        .get_section_content_by_name(&CStr::from_bytes_with_nul(b".debug_info\0")?)
        .context("Failed to find .debug_info section")?;
    let mut cursor = Cursor::new(debug_info_data);
    let mut compile_units = Vec::new();
    while !cursor.is_at_end() {
        compile_units.push(parse_compile_unit(&mut cursor, elf)?);
    }
    Ok(compile_units)
}

fn parse_compile_unit<'elf>(
    cursor: &mut Cursor<'elf>,
    elf: &'elf Elf,
) -> Result<CompileUnit<'elf>> {
    let start = cursor.position();
    let mut size: u32 = cursor
        .read_u32()
        .context("Failed to read size when trying to parse compile unit")?;
    let version: u16 = cursor
        .read_u16()
        .context("Failed to read version when trying to parse compile unit")?;
    let abbrev: u32 = cursor
        .read_u32()
        .context("Failed to read abbrev when trying to parse compile unit")?;
    let address_size: u8 = cursor
        .read_u8()
        .context("Failed to read address size when trying to parse compile unit")?;
    if size == 0xffffffff {
        return Err(anyhow!("Only DWARF32 is supported"));
    }
    if version != 4 {
        return Err(anyhow!("Only DWARF version 4 is supported"));
    }
    if address_size != 8 {
        return Err(anyhow!("Invalid address size for DWARF"));
    }
    // "because the reported size in the compile unit header doesn’t include the size field itself"
    size += std::mem::size_of::<u32>() as u32;
    let end = start + size as usize;
    // `data` is the DIE stream only — the CU header has already been consumed
    // by the reads above, so we slice from `cursor.position()` (which sits just
    // past the header) to `end`. This keeps all downstream offsets header-free.
    let compile_unit_data: &'elf [u8] = &cursor.bytes[cursor.position()..end];
    cursor.increment_cursor_by(end - cursor.position());
    Ok(CompileUnit {
        abbrev_offset: abbrev as usize,
        debug_info_offset: start,
        data: compile_unit_data,
        elf,
    })
}

// --- CompileUnit ---

impl<'elf> CompileUnit<'elf> {
    pub fn debug_info_offset(&self) -> usize {
        self.debug_info_offset
    }
    pub fn data(&self) -> &'elf [u8] {
        self.data
    }
    pub fn abbrev_offset(&self) -> usize {
        self.abbrev_offset
    }

    pub fn root<'dwarf>(
        &'dwarf self,
        abbrev_table_cache: &'dwarf mut AbbrevTableCache,
    ) -> Result<Die<'elf, 'dwarf>> {
        let mut cursor = Cursor::new(self.data);
        return parse_die(&mut cursor, &self, abbrev_table_cache);
    }

    fn root_internal<'dwarf>(
        &'dwarf self,
        abbrev_table: &'dwarf AbbrevTable,
    ) -> Result<Die<'elf, 'dwarf>> {
        let mut cursor = Cursor::new(self.data);
        return parse_die_raw(&mut cursor, &self, abbrev_table);
    }
}

// --- Die / DiePayload / DieChildrenIter ---

impl<'elf, 'b> Die<'elf, 'b> {
    pub fn children(&self) -> Option<DieChildrenIter<'elf, 'b>> {
        match self {
            Die::Null(_) => None,
            Die::NonNull(payload) => Some(payload.children()),
        }
    }

    /// Offset of the start of this DIE within `compile_unit.data`.
    pub fn position(&self) -> usize {
        match self {
            Die::Null(pos) => *pos,
            Die::NonNull(payload) => payload.position,
        }
    }

    pub fn tag(&self) -> Option<u64> {
        match self {
            Die::Null(_) => None,
            Die::NonNull(payload) => Some(payload.tag()),
        }
    }

    pub fn has_children(&self) -> bool {
        match self {
            Die::Null(_) => false,
            Die::NonNull(payload) => payload.has_children(),
        }
    }

    pub fn get_attr(&self, attr: u64) -> Option<Attr<'elf, 'b>> {
        let payload = match &self {
            Die::Null(_) => return None,
            Die::NonNull(die_payload) => die_payload,
        };
        payload.get_attr(attr)
    }

    pub fn low_pc(&self) -> Result<FileAddress<'elf>> {
        if let Some(attr) = self.get_attr(DwAt::Ranges as u64) {
            let range_list = attr.as_range_list()?;
            let first_entry = range_list
                .iter()
                .next()
                .ok_or(anyhow!(
                    "Failed to get the first entry out of the range list"
                ))
                .context("Failed to extract the first entry from the range list iterator")?;
            Ok(first_entry.low)
        } else if let Some(attr) = self.get_attr(DwAt::LowPc as u64) {
            attr.as_address()
        } else {
            Err(anyhow!("Failed to get DwAt::LowPc for attr"))
        }
    }

    pub fn high_pc(&self) -> Result<FileAddress<'elf>> {
        if let Some(attr) = self.get_attr(DwAt::Ranges as u64) {
            /*
            Building a Debugger. Page 329
            If we encounter a DW_AT_ranges attribute, we get the high address of the
            highest pair of addresses. To do this, we get an iterator to the first range,
            increment it until it points to the element before the end iterator (that is,
            the last element of the list), and return the high range of that pair. If we en-
            counter a DW_AT_high_pc attribute, we do the same as we used to, interpreting
            the attribute as either an address or an offset from the low program counter.
            Otherwise, we throw an exception.
             */
            let range_list = attr.as_range_list()?;
            let last_entry = range_list
                .iter()
                .last()
                .ok_or(anyhow!("Failed to get the last entry of the range_list"))
                .context("The last entry in the range list failed to parse")?;
            Ok(last_entry.high)
        } else if let Some(attr) = self.get_attr(DwAt::HighPc as u64) {
            /*
            Building a Debugger. Page 322
            For the high program counter value, we check the form. If the form is
            an address, we extract it. Otherwise, the form must be an offset from the
            low program counter, so we extract the low program counter and then offset
            it with the high program counter attribute as an integer.
            */
            let address: usize = {
                if attr.dw_form()? == DwForm::Addr {
                    attr.as_address()?.address
                } else {
                    self.low_pc()?.address + attr.as_int()? as usize
                }
            };
            Ok(FileAddress {
                elf_handle: attr.compile_unit.elf,
                address,
            })
        } else {
            Err(anyhow!("Failed to get DwAt::HighPc for attr"))
        }
    }

    fn contains<'otherelf>(&self, address: FileAddress<'otherelf>) -> bool {
        match self {
            Die::Null(_) => return false,
            Die::NonNull(die_payload) => {
                if die_payload.compile_unit.elf.path != address.elf_handle.path {
                    // Ensure that both elf objects are pointing to the same underlying file.
                    // It's very unlikely we'd be referencing two different objects but the provided
                    // FileAddress need not be constructed using the same Elf object as the Die.
                    return false;
                }
                if let Some(attr) = self.get_attr(DwAt::Ranges as u64) {
                    let range_list = attr
                        .as_range_list()
                        .expect("Expected to get range_list attr");
                    return range_list.contains(address);
                } else if let Some(_attr) = self.get_attr(DwAt::LowPc as u64) {
                    return self.low_pc().expect("Expected to get low_pc attr") <= address
                        && address < self.high_pc().expect("Expected to get high_pc attr");
                } else {
                    return false;
                }
            }
        }
    }
}

impl<'elf, 'dwarf> DiePayload<'elf, 'dwarf> {
    pub fn children(&self) -> DieChildrenIter<'elf, 'dwarf> {
        DieChildrenIter {
            compile_unit: self.compile_unit,
            abbrev_table: self.abbrev_table,
            current_offset: self.next,
            done: !self.abbrev.has_children,
        }
    }

    pub fn get_attr(&self, attr: u64) -> Option<Attr<'elf, 'dwarf>> {
        let specs = &self.abbrev.attr_specs;
        for (index, spec) in specs.iter().enumerate() {
            if spec.attr == attr {
                return Some(Attr {
                    form: spec.form,
                    attr_type: spec.attr,
                    compile_unit: self.compile_unit,
                    location_offset: self.attr_locations[index],
                    abbrev_table: self.abbrev_table,
                });
            }
        }
        None
    }

    pub fn tag(&self) -> u64 {
        self.abbrev.tag
    }

    pub fn has_children(&self) -> bool {
        self.abbrev.has_children
    }

    pub fn abbrev_code(&self) -> u64 {
        self.abbrev.code
    }

    pub fn attr_specs(&self) -> &[AttrSpec] {
        &self.abbrev.attr_specs
    }

    pub fn compile_unit(&self) -> &'dwarf CompileUnit<'elf> {
        self.compile_unit
    }
}

impl<'a, 'b> Iterator for DieChildrenIter<'a, 'b> {
    type Item = Result<Die<'a, 'b>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let die_data = self.compile_unit.data;
        let mut cursor = Cursor::new(die_data);
        cursor.increment_cursor_by(self.current_offset);

        match parse_die_raw(&mut cursor, self.compile_unit, self.abbrev_table) {
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
            Ok(Die::Null(_)) => {
                self.done = true;
                None
            }
            Ok(Die::NonNull(payload)) => {
                let next_sibling_offset: usize = if payload.abbrev.has_children {
                    if let Some(attr) = payload.get_attr(DwAt::Sibling as u64) {
                        // DW_AT_sibling is guaranteed to reference a DIE within the
                        // same CU, so a CU-local form lookup suffices and we avoid
                        // needing an AbbrevTableCache here.
                        /*
                        https://dwarfstd.org/doc/DWARF4.pdf Section 2.3
                        In cases where a producer of debugging information feels that it will be important for consumers
                        of that information to quickly scan chains of sibling entries, while ignoring the children of
                        individual siblings, that producer may attach a DW_AT_sibling attribute to any debugging
                        information entry. The value of this attribute is a reference to the sibling entry of the entry to
                        which the attribute is attached
                        */
                        match attr.as_cu_local_reference_position() {
                            Ok(pos) => pos,
                            Err(e) => {
                                self.done = true;
                                return Some(Err(e));
                            }
                        }
                    } else {
                        let mut skip_cursor = Cursor::new(die_data);
                        skip_cursor.increment_cursor_by(payload.next);
                        match skip_children(&mut skip_cursor, self.abbrev_table) {
                            Ok(()) => skip_cursor.position(),
                            Err(e) => {
                                self.done = true;
                                return Some(Err(e));
                            }
                        }
                    }
                } else {
                    payload.next
                };
                self.current_offset = next_sibling_offset;
                Some(Ok(Die::NonNull(payload)))
            }
        }
    }
}

fn parse_die<'elf, 'dwarf>(
    cursor: &mut Cursor,
    compile_unit: &'dwarf CompileUnit<'elf>,
    abbrev_table_cache: &'dwarf mut AbbrevTableCache,
) -> Result<Die<'elf, 'dwarf>> {
    let abbrev_table = abbrev_table_cache.get_table_at_offset(compile_unit.abbrev_offset)?;
    parse_die_raw(cursor, compile_unit, abbrev_table)
}

fn parse_die_raw<'elf, 'dwarf>(
    cursor: &mut Cursor,
    compile_unit: &'dwarf CompileUnit<'elf>,
    abbrev_table: &'dwarf AbbrevTable,
) -> Result<Die<'elf, 'dwarf>> {
    let position = cursor.position();
    let abbrev_code = cursor.uleb128()?;
    if abbrev_code == 0 {
        return Ok(Die::Null(position));
    }
    let abbrev: &Abbrev = abbrev_table
        .get(&abbrev_code)
        .context("Failed to get abbrev entry from CU's abbrev_table")?;
    let mut attr_locations = Vec::new();
    attr_locations.reserve(abbrev.attr_specs.len());
    for attr in &abbrev.attr_specs {
        attr_locations.push(cursor.position());
        cursor.skip_form(attr.form)?;
    }
    let next = cursor.position();
    Ok(Die::NonNull(DiePayload {
        position,
        next,
        compile_unit,
        abbrev,
        attr_locations,
        abbrev_table,
    }))
}

fn skip_children(cursor: &mut Cursor, abbrev_table: &AbbrevTable) -> Result<()> {
    loop {
        let code = cursor.uleb128()?;
        if code == 0 {
            return Ok(());
        }
        let abbrev = abbrev_table
            .get(&code)
            .ok_or_else(|| anyhow!("Unknown abbreviation code: {}", code))?;
        for attr in &abbrev.attr_specs {
            cursor.skip_form(attr.form)?;
        }
        if abbrev.has_children {
            skip_children(cursor, abbrev_table)?;
        }
    }
}

// --- Attr / AttrSpec ---

impl<'elf, 'dwarf> Attr<'elf, 'dwarf> {
    pub fn form(&self) -> u64 {
        self.form
    }

    pub fn attr_type(&self) -> u64 {
        self.attr_type
    }

    fn dw_form(&self) -> Result<DwForm> {
        u8::try_from(self.form)
            .ok()
            .and_then(|f| DwForm::try_from(f).ok())
            .ok_or_else(|| anyhow!("Unrecognized DWARF form: {:#x}", self.form))
    }

    pub fn as_address(&self) -> Result<FileAddress<'elf>> {
        if self.dw_form()? != DwForm::Addr {
            return Err(anyhow!("Invalid attr type. Expected DwForm::Addr"));
        }
        let mut cursor = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        let address = cursor.read_u64().context("Failed to extract u64")? as usize;
        Ok(FileAddress {
            elf_handle: self.compile_unit.elf,
            address,
        })
    }

    pub fn as_section_offset(&self) -> Result<u32> {
        if self.dw_form()? != DwForm::SecOffset {
            return Err(anyhow!("Invalid attr type. Expected DwForm::SecOffset"));
        }
        let mut cursor = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        Ok(cursor.read_u32().context("Failed to extract u32")?)
    }

    pub fn as_int(&self) -> Result<u64> {
        let mut cursor = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        match self.dw_form()? {
            DwForm::Data1 => Ok(cursor.read_u8()? as u64),
            DwForm::Data2 => Ok(cursor.read_u16()? as u64),
            DwForm::Data4 => Ok(cursor.read_u32()? as u64),
            DwForm::Data8 => cursor.read_u64(),
            DwForm::Udata => cursor.uleb128(),
            DwForm::Sdata => Ok(cursor.sleb128()? as u64),
            other => Err(anyhow!("Invalid form for as_int: {:?}", other)),
        }
    }

    pub fn as_block(&self) -> Result<&[u8]> {
        let mut cursor = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        let size = match self.dw_form()? {
            DwForm::Block1 => cursor.read_u8()? as usize,
            DwForm::Block2 => cursor.read_u16()? as usize,
            DwForm::Block4 => cursor.read_u32()? as usize,
            DwForm::Block => cursor.uleb128()? as usize,
            other => {
                return Err(anyhow!("Invalid form for as_block: {:?}", other));
            }
        };
        let start = self.location_offset + cursor.position();
        let end = start
            .checked_add(size)
            .ok_or_else(|| anyhow!("Block size overflow"))?;
        let buffer = self
            .compile_unit
            .data
            .get(start..end)
            .ok_or_else(|| anyhow!("Block extends past compile unit data"))?;
        Ok(buffer)
    }

    pub fn as_reference(
        &self,
        dwarf: &'elf Dwarf<'elf>,
        abbrev_cache: &'dwarf mut AbbrevTableCache<'elf>,
    ) -> Result<Die<'elf, 'dwarf>> {
        let mut cursor = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        let (target_cu, cu_relative_offset): (&'dwarf CompileUnit<'elf>, usize) =
            match self.dw_form()? {
                DwForm::Ref1 => (self.compile_unit, cursor.read_u8()? as usize),
                DwForm::Ref2 => (self.compile_unit, cursor.read_u16()? as usize),
                DwForm::Ref4 => (self.compile_unit, cursor.read_u32()? as usize),
                DwForm::Ref8 => (self.compile_unit, cursor.read_u64()? as usize),
                DwForm::RefUdata => (self.compile_unit, cursor.uleb128()? as usize),
                DwForm::RefAddr => {
                    /*
                    From https://dwarfstd.org/doc/DWARF4.pdf:
                    The second type of reference can identify any debugging information entry within a
                    .debug_info section; in particular, it may refer to an entry in a different compilation unit
                    from the unit containing the reference, and may refer to an entry in a different shared object.
                    This type of reference (DW_FORM_ref_addr) is an offset from the beginning of the
                    .debug_info section of the target executable or shared object; it is relocatable in a
                    relocatable object file and frequently relocated in an executable file or shared object.
                    */
                    // Offset in .debug_info
                    let abs_offset = cursor.read_u32()? as usize;
                    find_cu_containing(dwarf, abs_offset)?
                }
                other => {
                    return Err(anyhow!("Invalid form for as_reference: {:?}", other));
                }
            };
        // Reference offsets are measured from the start of the CU header, but
        // `compile_unit.data` no longer contains the header. Translate so the
        // parsed DIE's `position` matches the header-free convention.
        let data_offset = cu_relative_offset
            .checked_sub(COMPILE_UNIT_HEADER_SIZE)
            .ok_or_else(|| {
                anyhow!(
                    "Reference offset {:#x} points inside the CU header",
                    cu_relative_offset
                )
            })?;
        // The target CU may use a different abbrev table than `self.compile_unit`
        // (DW_FORM_ref_addr can cross CU boundaries), so look it up by the target's
        // abbrev_offset rather than reusing the caller's table.
        let abbrev_table = abbrev_cache.get_table_at_offset(target_cu.abbrev_offset)?;
        let mut reference_cursor = Cursor::new(target_cu.data);
        reference_cursor.increment_cursor_by(data_offset);
        parse_die_raw(&mut reference_cursor, target_cu, abbrev_table)
    }

    /// Reads a CU-local reference and returns the target DIE's position within
    /// `compile_unit.data`. Rejects `DW_FORM_ref_addr` (which may cross CU
    /// boundaries) — callers needing that must use [`Attr::as_reference`] with
    /// an abbrev table cache.
    pub fn as_cu_local_reference_position(&self) -> Result<usize> {
        let mut cursor = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        let cu_relative_offset = match self.dw_form()? {
            DwForm::Ref1 => cursor.read_u8()? as usize,
            DwForm::Ref2 => cursor.read_u16()? as usize,
            DwForm::Ref4 => cursor.read_u32()? as usize,
            DwForm::Ref8 => cursor.read_u64()? as usize,
            DwForm::RefUdata => cursor.uleb128()? as usize,
            other => {
                return Err(anyhow!("Form is not a CU-local reference: {:?}", other));
            }
        };
        cu_relative_offset
            .checked_sub(COMPILE_UNIT_HEADER_SIZE)
            .ok_or_else(|| {
                anyhow!(
                    "Reference offset {:#x} points inside the CU header",
                    cu_relative_offset
                )
            })
    }

    pub fn as_string(&'elf self) -> Result<&'elf CStr> {
        let mut cursor: Cursor<'elf> = Cursor::new(&self.compile_unit.data[self.location_offset..]);
        match self.dw_form()? {
            DwForm::String => {
                return cursor.read_string();
            }
            DwForm::Strp => {
                let offset = cursor.read_u32()? as usize;
                let string_table = self
                    .compile_unit
                    .elf
                    .get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_str\0")?)
                    .ok_or(anyhow!("Failed to find .debug_str section"))?;
                let mut cursor = Cursor::new(&string_table[offset..]);
                return cursor.read_string();
            }
            other => {
                return Err(anyhow!("Invalid form for as_string: {:?}", other));
            }
        }
    }

    pub fn as_range_list(&self) -> Result<RangeList<'elf, 'dwarf>> {
        let debug_ranges_bytes = self
            .compile_unit
            .elf
            .get_section_content_by_name(
                &CStr::from_bytes_until_nul(b".debug_ranges")
                    .expect("Bytes -> &CStr conversion failed"),
            )
            .ok_or(anyhow!("Failed to find .debug_ranges"))?;
        // Parse the offset stored at the current attribute position
        let offset = self.as_section_offset()? as usize;
        let data = &debug_ranges_bytes[offset..];
        let base_address = match self
            .compile_unit
            .root_internal(self.abbrev_table)?
            .get_attr(DwAt::LowPc as u64)
        {
            Some(attr) => attr.as_address()?,
            None => FileAddress {
                elf_handle: self.compile_unit.elf,
                address: 0usize,
            },
        };
        Ok(RangeList {
            compile_unit: self.compile_unit,
            data,
            base_address,
        })
    }
}

impl AttrSpec {
    pub fn attr(&self) -> u64 {
        self.attr
    }
    pub fn form(&self) -> u64 {
        self.form
    }
}

// --- Abbreviations ---

impl<'elf> AbbrevTableCache<'elf> {
    pub fn new(elf: &'elf Elf) -> AbbrevTableCache<'elf> {
        AbbrevTableCache {
            elf,
            tables: HashMap::new(),
        }
    }

    pub fn get_table_at_offset(&mut self, offset: usize) -> Result<&AbbrevTable> {
        if !self.tables.contains_key(&offset) {
            // Cache miss
            self.tables
                .insert(offset, parse_abbrev_table(self.elf, offset)?);
        }
        Ok(self.tables.get(&offset).unwrap())
    }
}

fn parse_abbrev_table(elf: &Elf, offset: usize) -> Result<AbbrevTable> {
    let section_buffer: &[u8] = elf
        .get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_abbrev\0").unwrap())
        .context(format!(
            "Failed to find the .debug_abbrev section in {:?}",
            &elf.path
        ))?;
    let mut cursor = Cursor::new(&section_buffer);
    cursor.increment_cursor_by(offset);
    let mut table = HashMap::<u64, Abbrev>::new();
    loop {
        // Parse one entry
        // We extract the ULEB128 for the code, the ULEB128 for the tag,
        // the 1-byte unsigned integer for the children flag (which will be either
        // 1 or 0), and the list of ULEB128 pairs of attribute types and forms,
        // terminated by a pair of 0s.
        let code = cursor.uleb128()?;
        if code == 0 {
            // Abbrev table is terminated by a single 0 byte (code 0).
            break;
        }
        let tag = cursor.uleb128()?;
        let has_children = cursor.read_u8()? > 0;
        let mut attr_specs = Vec::<AttrSpec>::new();
        loop {
            let attr = cursor.uleb128()?;
            let form = cursor.uleb128()?;
            if attr == 0 {
                // Attr, form list is terminated by a pair of 0s.
                break;
            }
            attr_specs.push(AttrSpec { attr, form });
        }
        table.insert(
            code,
            Abbrev {
                code,
                tag,
                has_children,
                attr_specs,
            },
        );
    }
    return Ok(table);
}

// --- Range Lists ---

impl<'elf, 'dwarf> RangeList<'elf, 'dwarf> {
    pub fn iter(&self) -> RangeListIterator<'elf, 'dwarf> {
        RangeListIterator {
            compile_unit: self.compile_unit,
            data: self.data,
            position: 0usize,
            base_address: self.base_address,
        }
    }

    fn contains(&self, address: FileAddress) -> bool {
        self.iter().find(|entry| entry.contains(address)).is_some()
    }
}

impl<'elf> RangeListEntry<'elf> {
    fn contains(&self, address: FileAddress) -> bool {
        return self.low <= address && address < self.high;
    }
}

impl<'elf, 'dwarf> Iterator for RangeListIterator<'elf, 'dwarf> {
    type Item = RangeListEntry<'elf>;

    fn next(&mut self) -> Option<Self::Item> {
        /*
        * The .debug_range section consists of a series of entries of three possible kinds:
            - regular range list entries
            - base address selectors(which change how we should interpret regular entries)
            - end-of-list indicators
        * All range list entries consist of two integers with a byte size identical to the address size of the machine(8 bytes, on x64).
            - Regular entries:
                - A beginning address offset relative to the current base address.
                - An ending address offset relative to the current base address.
            - Base address selectors
                - An integer with all bits set, which indicates that this entry is a base address selector.
                - An integer that sets the base address from which all future range list entries should be considered an offset.
                  (until the base address is changed again or the list ends)
            - End-of-list indicator has both integers set to 0.

         */
        const BASE_ADDRESS_FLAG: u64 = u64::MAX;
        let mut cursor = Cursor::new(&self.data[self.position..]);
        loop {
            let low: u64 = cursor
                .read_u64()
                .expect("Failed to extract range-list entry low");
            let high: u64 = cursor
                .read_u64()
                .expect("Failed to extract range-list entry high");
            if low == BASE_ADDRESS_FLAG {
                self.base_address = FileAddress {
                    elf_handle: self.compile_unit.elf,
                    address: high as usize,
                };
            } else if low == 0 && high == 0 {
                // Should end iteration as we're at the End-of-list indicator.
                return None;
            } else {
                self.position = cursor.position();
                return Some(RangeListEntry {
                    low: self.base_address + low as usize,
                    high: self.base_address + high as usize,
                });
            }
        }
    }
}
