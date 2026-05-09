use crate::cursor::Cursor;
use crate::elf::Elf;
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
type AbbrevTable = HashMap<u64 /* abbreviation code*/, Abbrev>;
struct AbbrevTableCache<'a> {
    elf: &'a Elf,
    tables: HashMap<usize /*offset into the .debug_abbrev section*/, AbbrevTable>,
}

struct CompileUnit<'elf> {
    abbrev_offset: usize,
    data: &'elf [u8],
}

struct Dwarf<'elf> {
    elf: &'elf Elf,
    compile_units: Vec<CompileUnit<'elf>>,
}

///  Debugging Information Entry
struct DiePayload<'a, 'b> {
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
}

enum Die<'a, 'b> {
    Null(usize),
    NonNull(DiePayload<'a, 'b>),
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
    let mut code: u64;
    loop {
        // Parse one entry
        // We extract the ULEB128 for the code, the ULEB128 for the tag,
        // the 1-byte unsigned integer for the children flag (which will be either
        // 1 or 0), and the list of ULEB128 pairs of attribute types and forms,
        // terminated by a pair of 0s.
        code = cursor.uleb128()?;
        let tag = cursor.uleb128()?;
        let has_children = cursor.read_u8()? > 0;
        let mut attr_specs = Vec::<AttrSpec>::new();
        let mut attr: u64;
        loop {
            attr = cursor.uleb128()?;
            let form = cursor.uleb128()?;
            if attr != 0 {
                attr_specs.push(AttrSpec { attr, form });
            }
            if attr == 0 {
                // Attr, form list is terminated by a 0
                break;
            }
        }
        if code != 0 {
            table.insert(
                code,
                Abbrev {
                    code,
                    tag,
                    has_children,
                    attr_specs,
                },
            );
        } else {
            // Abbrev table entry is terminated by a 0
            break;
        }
    }
    return Ok(table);
}

fn parse_compile_unit<'elf>(cursor: &mut Cursor<'elf>) -> Result<CompileUnit<'elf>> {
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
    let compile_unit_data: &'elf [u8] = &cursor.bytes[start..start + size as usize];
    cursor.increment_cursor_by(size as usize);
    Ok(CompileUnit {
        abbrev_offset: abbrev as usize,
        data: compile_unit_data,
    })
}

fn parse_compile_units<'elf>(elf: &'elf Elf) -> Result<Vec<CompileUnit<'elf>>> {
    let debug_info_data = elf
        .get_section_content_by_name(&CStr::from_bytes_with_nul(b".debug_info\0")?)
        .context("Failed to find .debug_info section")?;
    let mut cursor = Cursor::new(debug_info_data);
    let mut compile_units = Vec::new();
    while !cursor.is_at_end() {
        compile_units.push(parse_compile_unit(&mut cursor)?);
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

fn parse_die<'a, 'b>(
    cursor: &mut Cursor,
    compile_unit: &'a CompileUnit,
    abbrev_table_cache: &'b mut AbbrevTableCache,
) -> Result<Die<'a, 'b>> {
    let position = cursor.position();
    let abbrev_code = cursor.uleb128()?;
    if abbrev_code == 0 {
        return Ok(Die::Null(position));
    }
    let abbrev_table = abbrev_table_cache.get_table_at_offset(compile_unit.abbrev_offset)?;
    let abbrev: &Abbrev = abbrev_table
        .get(&abbrev_code)
        .context("Failed to get abbrev entry from CU's abbrev_table")?;
    let mut attr_locations = Vec::new();
    attr_locations.reserve(abbrev.attr_specs.len());
    for attr in &abbrev.attr_specs {
        attr_locations.push(cursor.position());
        cursor.skip_form(attr.form);
    }
    let next = cursor.position();
    return Ok(Die::NonNull(DiePayload {
        position,
        next,
        compile_unit,
        abbrev,
        attr_locations,
    }));
}
