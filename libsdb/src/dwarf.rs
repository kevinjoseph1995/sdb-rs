use crate::cursor;
use crate::dwarf_constants::DwForm;
use crate::elf::Elf;
use crate::{address::FileAddress, cursor::Cursor};
use anyhow::{Context, Result, anyhow};
use std::{collections::HashMap, ffi::CStr};

pub struct AttrSpec {
    attr: u64,
    form: u64,
}

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

pub struct CompileUnit<'elf> {
    abbrev_offset: usize,
    data: &'elf [u8],
    elf: &'elf Elf,
}

pub struct Dwarf<'elf> {
    elf: &'elf Elf,
    pub compile_units: Vec<CompileUnit<'elf>>,
}

///  Debugging Information Entry
pub struct DiePayload<'a, 'b> {
    /// This is the offset into the .debug_info section
    position: usize,
    /// This is the offset of either a sibling or child of this DIE
    next: usize,
    /// The compile unit that owns this Die
    compile_unit: &'a CompileUnit<'a>,
    /// abbrev entry for this DIE
    abbrev: &'b Abbrev,
    /// Locations into the .debug_info section where the attrs live.
    attr_locations: Vec<usize>,
    /// Abbrev table
    abbrev_table: &'b AbbrevTable,
}

pub enum Die<'a, 'b> {
    Null(usize),
    NonNull(DiePayload<'a, 'b>),
}

pub struct Attr<'elf> {
    form: u64,
    attr_type: u64,
    compile_unit: &'elf CompileUnit<'elf>,
    location_offset: usize, // Offset in compile_unit.data
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
    let compile_unit_data: &'elf [u8] = &cursor.bytes[start..end];
    cursor.increment_cursor_by(end - cursor.position());
    Ok(CompileUnit {
        abbrev_offset: abbrev as usize,
        data: compile_unit_data,
        elf,
    })
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

impl<'a> Dwarf<'a> {
    pub fn new<'elf, 'b>(elf: &'elf Elf) -> Result<Dwarf<'elf>> {
        Ok(Dwarf {
            elf,
            compile_units: parse_compile_units(elf)?,
        })
    }
}

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

impl<'elf> CompileUnit<'elf> {
    pub fn root<'a, 'b>(
        &'a self,
        abbrev_table_cache: &'b mut AbbrevTableCache,
    ) -> Result<Die<'a, 'b>> {
        // Compile unit header size
        const HEADER_SIZE: usize = 11;
        let mut cursor = Cursor::new(&self.data[HEADER_SIZE..]);
        return parse_die(&mut cursor, &self, abbrev_table_cache);
    }
}

fn parse_die_raw<'a, 'b>(
    cursor: &mut Cursor,
    compile_unit: &'a CompileUnit,
    abbrev_table: &'b AbbrevTable,
) -> Result<Die<'a, 'b>> {
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

fn parse_die<'a, 'b>(
    cursor: &mut Cursor,
    compile_unit: &'a CompileUnit,
    abbrev_table_cache: &'b mut AbbrevTableCache,
) -> Result<Die<'a, 'b>> {
    let abbrev_table = abbrev_table_cache.get_table_at_offset(compile_unit.abbrev_offset)?;
    parse_die_raw(cursor, compile_unit, abbrev_table)
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

pub struct DieChildrenIter<'a, 'b> {
    compile_unit: &'a CompileUnit<'a>,
    abbrev_table: &'b AbbrevTable,
    current_offset: usize,
    done: bool,
}

impl<'a, 'b> Iterator for DieChildrenIter<'a, 'b> {
    type Item = Result<Die<'a, 'b>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        const HEADER_SIZE: usize = 11;
        let die_data = &self.compile_unit.data[HEADER_SIZE..];
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
                let next_sibling_offset = if payload.abbrev.has_children {
                    let mut skip_cursor = Cursor::new(die_data);
                    skip_cursor.increment_cursor_by(payload.next);
                    match skip_children(&mut skip_cursor, self.abbrev_table) {
                        Ok(()) => skip_cursor.position(),
                        Err(e) => {
                            self.done = true;
                            return Some(Err(e));
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

impl<'a, 'b> DiePayload<'a, 'b> {
    pub fn children(&self) -> DieChildrenIter<'a, 'b> {
        DieChildrenIter {
            compile_unit: self.compile_unit,
            abbrev_table: self.abbrev_table,
            current_offset: self.next,
            done: !self.abbrev.has_children,
        }
    }
}

impl<'a, 'b> Die<'a, 'b> {
    pub fn children(&self) -> Option<DieChildrenIter<'a, 'b>> {
        match self {
            Die::Null(_) => None,
            Die::NonNull(payload) => Some(payload.children()),
        }
    }

    fn get_attr(&self, attr: u64) -> Option<Attr<'a>> {
        let payload = match &self {
            Die::Null(_) => return None,
            Die::NonNull(die_payload) => die_payload,
        };
        let specs = &payload.abbrev.attr_specs;
        for (index, spec) in specs.iter().enumerate() {
            if spec.attr == attr {
                return Some(Attr {
                    form: spec.form,
                    attr_type: spec.attr,
                    compile_unit: payload.compile_unit,
                    location_offset: payload.attr_locations[index],
                });
            }
        }
        None
    }
}

impl<'elf> Attr<'elf> {
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
}
