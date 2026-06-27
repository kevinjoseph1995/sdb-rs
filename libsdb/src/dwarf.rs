use crate::dwarf_constants::{DwAt, DwForm, DwTag};
use crate::elf::Elf;
use crate::{address::FileAddress, cursor::Cursor};
use anyhow::{Context, Result, anyhow};
use std::cell::RefCell;
use std::rc::Rc;
use std::{collections::HashMap, ffi::CStr};

/// Size of the DWARF v4 compile unit header in DWARF32 format:
/// unit_length (4) + version (2) + debug_abbrev_offset (4) + address_size (1).
pub const COMPILE_UNIT_HEADER_SIZE: usize = 11;

// --- Top-level DWARF handle
pub struct Dwarf<'elf> {
    elf: &'elf Elf,
    /// The whole `.debug_info` section. CU `data_range`s index into this.
    debug_info: &'elf [u8],
    compile_units: Vec<CompileUnit>,
    function_index: HashMap<String, Vec<IndexEntry>>,
    abbrev_table_cache: RefCell<HashMap<usize, Rc<AbbrevTable>>>,
}

pub struct CompileUnit {
    abbrev_offset: usize,
    /// Start offset of this CU (including its header) within the .debug_info section.
    /// Used to resolve `DW_FORM_ref_addr` references that point into other CUs.
    debug_info_offset: usize,
    /// Range of this CU's DIE bytes within the `.debug_info` section, with the
    /// [`COMPILE_UNIT_HEADER_SIZE`]-byte header already stripped. All offsets stored
    /// in this module (DIE `position`/`next`, `attr_locations`) are indices into the
    /// slice this range resolves to (see [`Dwarf::cu_data`]).
    data_range: std::ops::Range<usize>,
}

struct IndexEntry {
    /// Index into [`Dwarf::compile_units`] of the owning CU.
    cu_index: usize,
    /// Offset of the DIE within that CU's `data`.
    offset: usize,
}

// --- Debugging Information Entries
pub enum Die<'dw, 'elf> {
    Null(
        usize, /* Offset of the start of this DIE within the CU's `data` */
    ),
    NonNull(DiePayload<'dw, 'elf>),
}

pub struct DiePayload<'dw, 'elf> {
    /// Offset of the start of this DIE within the CU's `data`.
    position: usize,
    /// Offset (within the CU's `data`) of either the next sibling or the
    /// first child of this DIE.
    next: usize,
    /// Index into [`Dwarf::compile_units`] of the CU that owns this Die.
    cu_index: usize,
    /// abbrev entry for this DIE
    abbrev: Rc<Abbrev>,
    /// Offsets within the CU's `data` where each attribute's value bytes live.
    attr_locations: Vec<usize>,
    /// Abbrev table
    abbrev_table: Rc<AbbrevTable>,
    /// Borrow of the owning Dwarf, for cross-CU references and abbrev lookups.
    dwarf: &'dw Dwarf<'elf>,
}

pub struct DieChildrenIter<'dw, 'elf> {
    cu_index: usize,
    abbrev_table: Rc<AbbrevTable>,
    current_offset: usize,
    done: bool,
    dwarf: &'dw Dwarf<'elf>,
}

// --- Attributes

pub struct Attr<'dw, 'elf> {
    form: u64,
    attr_type: u64,
    cu_index: usize,
    location_offset: usize, // Offset in the CU's `data`
    abbrev_table: Rc<AbbrevTable>,
    dwarf: &'dw Dwarf<'elf>,
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
pub type AbbrevTable = HashMap<u64 /* abbreviation code*/, Rc<Abbrev>>;

// --- Range list related types

pub struct RangeList<'elf> {
    elf: &'elf Elf,
    data: &'elf [u8],
    base_address: FileAddress<'elf>,
}

pub struct RangeListEntry<'elf> {
    low: FileAddress<'elf>,
    high: FileAddress<'elf>,
}

pub struct RangeListIterator<'elf> {
    elf: &'elf Elf,
    data: &'elf [u8],
    position: usize,
    base_address: FileAddress<'elf>,
}

// ===================================================================

// --- Dwarf ---

impl<'elf> Dwarf<'elf> {
    pub fn new(elf: &'elf Elf) -> Result<Dwarf<'elf>> {
        let debug_info = elf
            .get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_info\0")?)
            .context("Failed to find .debug_info section")?;
        let compile_units = parse_compile_units(debug_info)?;
        let mut dwarf = Dwarf {
            elf,
            debug_info,
            compile_units,
            function_index: HashMap::new(),
            abbrev_table_cache: RefCell::new(HashMap::new()),
        };
        // Build the function index eagerly. The walk only reads `compile_units`
        // and the abbrev cache, so the (empty) `function_index` is never observed
        // before it is assigned.
        dwarf.function_index = dwarf.build_function_index();
        Ok(dwarf)
    }

    pub fn compile_units(&self) -> &[CompileUnit] {
        &self.compile_units
    }

    /// Resolves a CU's DIE bytes (header stripped) within the `.debug_info` section.
    fn cu_data(&self, cu_index: usize) -> &'elf [u8] {
        &self.debug_info[self.compile_units[cu_index].data_range.clone()]
    }

    fn get_abbrev_table(&self, offset: usize) -> Result<Rc<AbbrevTable>> {
        if let Some(table) = self.abbrev_table_cache.borrow().get(&offset) {
            return Ok(Rc::clone(table));
        }
        let table = Rc::new(parse_abbrev_table(self.elf, offset)?);
        self.abbrev_table_cache
            .borrow_mut()
            .insert(offset, Rc::clone(&table));
        Ok(table)
    }

    pub fn root_of<'dw>(&'dw self, cu_index: usize) -> Result<Die<'dw, 'elf>> {
        let table = self.get_abbrev_table(self.compile_units[cu_index].abbrev_offset)?;
        let mut cursor = Cursor::new(self.cu_data(cu_index));
        parse_die_raw(&mut cursor, self, cu_index, table)
    }

    pub fn compile_unit_containing_address(&self, address: FileAddress<'elf>) -> Option<usize> {
        (0..self.compile_units.len()).find(|&cu_index| {
            self.root_of(cu_index)
                .expect("Failed to extract root DIE from compile unit")
                .contains(address)
        })
    }

    pub fn function_containing_address<'dw>(
        &'dw self,
        address: FileAddress<'elf>,
    ) -> Option<Die<'dw, 'elf>> {
        let entries: Vec<(usize, usize)> = self
            .function_index
            .values()
            .flatten()
            .map(|e| (e.cu_index, e.offset))
            .collect();

        for (cu_index, offset) in entries {
            let abbrev_table = self
                .get_abbrev_table(self.compile_units[cu_index].abbrev_offset)
                .expect("Failed to get abbrev table");
            let mut cursor = Cursor::new(&self.cu_data(cu_index)[offset..]);
            let die = parse_die_raw(&mut cursor, self, cu_index, abbrev_table)
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
        None
    }

    pub fn find_functions<'dw>(&'dw self, function_name: &str) -> Vec<Die<'dw, 'elf>> {
        let entries: Vec<(usize, usize)> = match self.function_index.get(function_name) {
            Some(index_entries) => index_entries
                .iter()
                .map(|e| (e.cu_index, e.offset))
                .collect(),
            None => return Vec::new(),
        };

        entries
            .into_iter()
            .map(|(cu_index, offset)| {
                let abbrev_table = self
                    .get_abbrev_table(self.compile_units[cu_index].abbrev_offset)
                    .expect("Failed to get abbrev table");
                let mut cursor = Cursor::new(&self.cu_data(cu_index)[offset..]);
                parse_die_raw(&mut cursor, self, cu_index, abbrev_table)
                    .expect("Failed to parse DIE")
            })
            .collect()
    }

    fn build_function_index(&self) -> HashMap<String, Vec<IndexEntry>> {
        let mut index = HashMap::new();
        for cu_index in 0..self.compile_units.len() {
            let die = self
                .root_of(cu_index)
                .expect("Failed to get root of compile unit");
            Self::index_die(die, &mut index);
        }
        index
    }

    fn index_die(die: Die<'_, 'elf>, index: &mut HashMap<String, Vec<IndexEntry>>) {
        let has_range: bool = match die.get_attr(DwAt::LowPc as u64) {
            Some(_) => true,
            None => false,
        } || match die.get_attr(DwAt::Ranges as u64) {
            Some(_) => true,
            None => false,
        };

        let (is_function, die_payload): (bool, Option<&DiePayload>) = match &die {
            Die::Null(_) => (false, None),
            Die::NonNull(die_payload) => (
                die_payload.abbrev.tag == DwTag::Subprogram as u64
                    || die_payload.abbrev.tag == DwTag::InlinedSubroutine as u64,
                Some(die_payload),
            ),
        };

        if is_function && has_range {
            if let Some(name) = die.name() {
                let die_payload = die_payload.expect("This should not happen");
                let entry = IndexEntry {
                    cu_index: die_payload.cu_index,
                    offset: die_payload.position,
                };
                index.entry(name).or_insert_with(Vec::new).push(entry);
            }
        }

        for child in match die.children() {
            Some(iterator) => iterator,
            None => return,
        } {
            let child = child.expect("Failed to parse children of DIE");
            Self::index_die(child, index);
        }
    }
}

fn find_cu_containing(dwarf: &Dwarf<'_>, abs_offset: usize) -> Result<(usize, usize)> {
    let cu_index = dwarf
        .compile_units
        .iter()
        .position(|cu| {
            // `data` no longer includes the CU header, so the CU's footprint
            // in .debug_info is `[debug_info_offset, debug_info_offset + header + data)`.
            abs_offset >= cu.debug_info_offset
                && abs_offset
                    < cu.debug_info_offset + COMPILE_UNIT_HEADER_SIZE + cu.data_range.len()
        })
        .ok_or_else(|| anyhow!("RefAddr {:#x} not in any compile unit", abs_offset))?;
    let cu = &dwarf.compile_units[cu_index];
    Ok((cu_index, abs_offset - cu.debug_info_offset))
}

fn parse_compile_units(debug_info: &[u8]) -> Result<Vec<CompileUnit>> {
    let mut cursor = Cursor::new(debug_info);
    let mut compile_units = Vec::new();
    while !cursor.is_at_end() {
        compile_units.push(parse_compile_unit(&mut cursor)?);
    }
    Ok(compile_units)
}

fn parse_compile_unit(cursor: &mut Cursor<'_>) -> Result<CompileUnit> {
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
    // "because the reported size in the compile unit header doesn't include the size field itself"
    size += std::mem::size_of::<u32>() as u32;
    let end = start + size as usize;
    // `data_range` covers the DIE stream only — the CU header has already been
    // consumed by the reads above, so we start at `cursor.position()` (which sits
    // just past the header). This keeps all downstream offsets header-free.
    let data_range = cursor.position()..end;
    cursor.increment_cursor_by(end - cursor.position());
    Ok(CompileUnit {
        abbrev_offset: abbrev as usize,
        debug_info_offset: start,
        data_range,
    })
}

// --- CompileUnit ---

impl CompileUnit {
    pub fn debug_info_offset(&self) -> usize {
        self.debug_info_offset
    }
    pub fn abbrev_offset(&self) -> usize {
        self.abbrev_offset
    }
}

// --- Die / DiePayload / DieChildrenIter ---

impl<'dw, 'elf> Die<'dw, 'elf> {
    pub fn children(&self) -> Option<DieChildrenIter<'dw, 'elf>> {
        match self {
            Die::Null(_) => None,
            Die::NonNull(payload) => Some(payload.children()),
        }
    }

    /// Offset of the start of this DIE within the CU's `data`.
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

    pub fn get_attr(&self, attr: u64) -> Option<Attr<'dw, 'elf>> {
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
                elf_handle: attr.dwarf.elf,
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
                if die_payload.dwarf.elf.path != address.elf_handle.path {
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

    pub fn name(&self) -> Option<String> {
        let payload = match &self {
            Die::Null(_) => {
                return None;
            }
            Die::NonNull(die_payload) => die_payload,
        };

        if let Some(attr) = self.get_attr(DwAt::Name as u64) {
            return Some(
                attr.as_string()
                    .expect("Failed to get string attribute")
                    .to_str()
                    .expect("CStr -> str conversion failed")
                    .to_string(),
            );
        }
        if let Some(attr) = self.get_attr(DwAt::Specification as u64) {
            let referenced_die: Die<'dw, 'elf> = attr
                .as_reference()
                .expect("Failed to get referenced DIE with DwAt::Specification");
            return referenced_die.name();
        }

        if let Some(attr) = self.get_attr(DwAt::AbstractOrigin as u64) {
            let referenced_die: Die<'dw, 'elf> = attr
                .as_reference()
                .expect("Failed to get referenced DIE with DwAt::AbstractOrigin");
            return referenced_die.name();
        }
        return None;
    }
}

impl<'dw, 'elf> DiePayload<'dw, 'elf> {
    pub fn children(&self) -> DieChildrenIter<'dw, 'elf> {
        DieChildrenIter {
            cu_index: self.cu_index,
            abbrev_table: Rc::clone(&self.abbrev_table),
            current_offset: self.next,
            done: !self.abbrev.has_children,
            dwarf: self.dwarf,
        }
    }

    pub fn get_attr(&self, attr: u64) -> Option<Attr<'dw, 'elf>> {
        let specs = &self.abbrev.attr_specs;
        for (index, spec) in specs.iter().enumerate() {
            if spec.attr == attr {
                return Some(Attr {
                    form: spec.form,
                    attr_type: spec.attr,
                    cu_index: self.cu_index,
                    location_offset: self.attr_locations[index],
                    abbrev_table: Rc::clone(&self.abbrev_table),
                    dwarf: self.dwarf,
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

    pub fn compile_unit(&self) -> &'dw CompileUnit {
        &self.dwarf.compile_units[self.cu_index]
    }
}

impl<'dw, 'elf> Iterator for DieChildrenIter<'dw, 'elf> {
    type Item = Result<Die<'dw, 'elf>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let die_data = self.dwarf.cu_data(self.cu_index);
        let mut cursor = Cursor::new(die_data);
        cursor.increment_cursor_by(self.current_offset);

        match parse_die_raw(
            &mut cursor,
            self.dwarf,
            self.cu_index,
            Rc::clone(&self.abbrev_table),
        ) {
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
                        match skip_children(&mut skip_cursor, &self.abbrev_table) {
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

fn parse_die_raw<'dw, 'elf>(
    cursor: &mut Cursor,
    dwarf: &'dw Dwarf<'elf>,
    cu_index: usize,
    abbrev_table: Rc<AbbrevTable>,
) -> Result<Die<'dw, 'elf>> {
    let position = cursor.position();
    let abbrev_code = cursor.uleb128()?;
    if abbrev_code == 0 {
        return Ok(Die::Null(position));
    }
    let abbrev: Rc<Abbrev> = abbrev_table
        .get(&abbrev_code)
        .context("Failed to get abbrev entry from CU's abbrev_table")?
        .clone();
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
        cu_index,
        abbrev,
        attr_locations,
        abbrev_table,
        dwarf,
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

impl<'dw, 'elf> Attr<'dw, 'elf> {
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
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
        let address = cursor.read_u64().context("Failed to extract u64")? as usize;
        Ok(FileAddress {
            elf_handle: self.dwarf.elf,
            address,
        })
    }

    pub fn as_section_offset(&self) -> Result<u32> {
        if self.dw_form()? != DwForm::SecOffset {
            return Err(anyhow!("Invalid attr type. Expected DwForm::SecOffset"));
        }
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
        Ok(cursor.read_u32().context("Failed to extract u32")?)
    }

    pub fn as_int(&self) -> Result<u64> {
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
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
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
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
            .dwarf
            .cu_data(self.cu_index)
            .get(start..end)
            .ok_or_else(|| anyhow!("Block extends past compile unit data"))?;
        Ok(buffer)
    }

    pub fn as_reference(&self) -> Result<Die<'dw, 'elf>> {
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
        let (target_cu_index, cu_relative_offset): (usize, usize) = match self.dw_form()? {
            DwForm::Ref1 => (self.cu_index, cursor.read_u8()? as usize),
            DwForm::Ref2 => (self.cu_index, cursor.read_u16()? as usize),
            DwForm::Ref4 => (self.cu_index, cursor.read_u32()? as usize),
            DwForm::Ref8 => (self.cu_index, cursor.read_u64()? as usize),
            DwForm::RefUdata => (self.cu_index, cursor.uleb128()? as usize),
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
                find_cu_containing(self.dwarf, abs_offset)?
            }
            other => {
                return Err(anyhow!("Invalid form for as_reference: {:?}", other));
            }
        };
        // Reference offsets are measured from the start of the CU header, but
        // the CU's `data` no longer contains the header. Translate so the
        // parsed DIE's `position` matches the header-free convention.
        let data_offset = cu_relative_offset
            .checked_sub(COMPILE_UNIT_HEADER_SIZE)
            .ok_or_else(|| {
                anyhow!(
                    "Reference offset {:#x} points inside the CU header",
                    cu_relative_offset
                )
            })?;
        // The target CU may use a different abbrev table than this attr's CU
        // (DW_FORM_ref_addr can cross CU boundaries), so look it up by the target's
        // abbrev_offset rather than reusing the caller's table.
        let target_abbrev_offset = self.dwarf.compile_units[target_cu_index].abbrev_offset;
        let abbrev_table = self.dwarf.get_abbrev_table(target_abbrev_offset)?;
        let mut reference_cursor = Cursor::new(self.dwarf.cu_data(target_cu_index));
        reference_cursor.increment_cursor_by(data_offset);
        parse_die_raw(
            &mut reference_cursor,
            self.dwarf,
            target_cu_index,
            abbrev_table,
        )
    }

    /// Reads a CU-local reference and returns the target DIE's position within
    /// the CU's `data`. Rejects `DW_FORM_ref_addr` (which may cross CU
    /// boundaries) — callers needing cross-CU references must use [`Attr::as_reference`].
    pub fn as_cu_local_reference_position(&self) -> Result<usize> {
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
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

    pub fn as_string(&self) -> Result<&'elf CStr> {
        let mut cursor: Cursor<'elf> = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
        match self.dw_form()? {
            DwForm::String => {
                return cursor.read_string();
            }
            DwForm::Strp => {
                let offset = cursor.read_u32()? as usize;
                let string_table = self
                    .dwarf
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

    pub fn as_range_list(&self) -> Result<RangeList<'elf>> {
        let debug_ranges_bytes = self
            .dwarf
            .elf
            .get_section_content_by_name(
                &CStr::from_bytes_until_nul(b".debug_ranges")
                    .expect("Bytes -> &CStr conversion failed"),
            )
            .ok_or(anyhow!("Failed to find .debug_ranges"))?;
        // Parse the offset stored at the current attribute position
        let offset = self.as_section_offset()? as usize;
        let data = &debug_ranges_bytes[offset..];
        let base_address = {
            let mut root_cursor = Cursor::new(self.dwarf.cu_data(self.cu_index));
            let root = parse_die_raw(
                &mut root_cursor,
                self.dwarf,
                self.cu_index,
                Rc::clone(&self.abbrev_table),
            )?;
            match root.get_attr(DwAt::LowPc as u64) {
                Some(attr) => attr.as_address()?,
                None => FileAddress {
                    elf_handle: self.dwarf.elf,
                    address: 0usize,
                },
            }
        };
        Ok(RangeList {
            elf: self.dwarf.elf,
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

fn parse_abbrev_table(elf: &Elf, offset: usize) -> Result<AbbrevTable> {
    let section_buffer: &[u8] = elf
        .get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_abbrev\0").unwrap())
        .context(format!(
            "Failed to find the .debug_abbrev section in {:?}",
            &elf.path
        ))?;
    let mut cursor = Cursor::new(&section_buffer);
    cursor.increment_cursor_by(offset);
    let mut table = HashMap::<u64, Rc<Abbrev>>::new();
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
            Rc::new(Abbrev {
                code,
                tag,
                has_children,
                attr_specs,
            }),
        );
    }
    return Ok(table);
}

// --- Range Lists ---

impl<'elf> RangeList<'elf> {
    pub fn iter(&self) -> RangeListIterator<'elf> {
        RangeListIterator {
            elf: self.elf,
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

impl<'elf> Iterator for RangeListIterator<'elf> {
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
                    elf_handle: self.elf,
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
