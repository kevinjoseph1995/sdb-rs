use crate::dwarf_constants::{DwAt, DwForm, DwLne, DwLns, DwTag};
use crate::elf::Elf;
use crate::{address::FileAddress, cursor::Cursor};
use anyhow::{Context, Result, anyhow};
use nix::NixPath;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::{collections::HashMap, ffi::CStr};

/// Size of the DWARF v4 compile unit header in DWARF32 format:
/// unit_length (4) + version (2) + debug_abbrev_offset (4) + address_size (1).
pub const COMPILE_UNIT_HEADER_SIZE: usize = 11;

// --- Top-level DWARF handle
pub struct Dwarf {
    elf: Rc<Elf>,
    /// The compile units parsed from `.debug_info`.
    ///
    /// `compile_units` and `line_tables` are always the same length, and
    /// entries at the same index are tied together: `line_tables[i]` is the
    /// line table for `compile_units[i]` (or `None` when that compile unit has
    /// no line program). This parallel-vector design deviates from the book,
    /// which nests the line table inside the compile unit, but it keeps the
    /// lifetimes easier to work with and reason about at the `Dwarf` level.
    compile_units: Vec<CompileUnit>,
    /// The line table for each compile unit, indexed in lockstep with
    /// `compile_units`. See the note on `compile_units`.
    line_tables: Vec<Option<LineTable>>,
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
pub enum Die<'dw> {
    Null(
        usize, /* Offset of the start of this DIE within the CU's `data` */
    ),
    NonNull(DiePayload<'dw>),
}

pub struct DiePayload<'dw> {
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
    dwarf: &'dw Dwarf,
}

pub struct DieChildrenIter<'dw> {
    cu_index: usize,
    abbrev_table: Rc<AbbrevTable>,
    current_offset: usize,
    done: bool,
    dwarf: &'dw Dwarf,
}

// --- Attributes

pub struct Attr<'dw> {
    form: u64,
    attr_type: u64,
    cu_index: usize,
    location_offset: usize, // Offset in the CU's `data`
    abbrev_table: Rc<AbbrevTable>,
    dwarf: &'dw Dwarf,
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
    /// Offset of this range list within the `.debug_ranges` section.
    offset: usize,
    base_address: FileAddress<'elf>,
}

pub struct RangeListEntry<'elf> {
    low: FileAddress<'elf>,
    high: FileAddress<'elf>,
}

pub struct RangeListIterator<'elf> {
    elf: &'elf Elf,
    /// Offset of the range list within the `.debug_ranges` section.
    offset: usize,
    /// Position within the range list, relative to `offset`.
    position: usize,
    base_address: FileAddress<'elf>,
}

struct FileEntry {
    path: std::path::PathBuf,
    modification_time: usize,
    file_length: usize,
}

struct LineTable {
    /// The range into .debug_line that stores the bytes of the stream of opcodes that follows the line-table header.
    data_range: std::ops::Range<usize>,
    default_is_statement: bool,
    /// The minimum value that special opcodes can add to the line register.
    line_base: i8,
    /// The range of values that special opcodes can add to the line register.
    line_range: u8,
    /// The number assigned to the first special opcode.
    opcode_base: u8,
    include_directories: Vec<std::path::PathBuf>,
    /// The compilation directory (DW_AT_comp_dir of the owning CU's root DIE),
    /// used to resolve relative file paths — including those introduced at
    /// runtime by DW_LNE_define_file during iteration.
    comp_dir: std::path::PathBuf,
    /// Set once the first iteration has appended any DW_LNE_define_file entries
    /// to `file_entries`. Later iterations still parse those opcodes but skip the
    /// push, so re-iterating never accumulates duplicate entries.
    define_files_loaded: bool,
    file_entries: Vec<FileEntry>,
}
#[derive(Clone)]
struct LineTableEntry<'elf> {
    /// Address of the machine instruction this row describes.
    address: FileAddress<'elf>,
    /// 1-based index into the line table's `file_entries` list identifying the
    /// source file. DWARF starts file numbering at 1.
    file_index: u64,
    /// Source line number (1-based; 0 means the instruction cannot be attributed
    /// to any source line).
    line: u64,
    /// Source column number (0 means the whole line / no column info).
    column: u64,
    /// Whether this row is a recommended breakpoint location (a statement boundary).
    is_stmt: bool,
    /// Whether this row starts a basic block.
    basic_block_start: bool,
    /// Whether this row is the end of a sequence of instructions, so `address` is
    /// the first byte past the sequence and the other fields carry no meaning.
    end_sequence: bool,
    /// Whether this row is a recommended breakpoint location just after a
    /// function's prologue.
    prologue_end: bool,
    /// Whether this row is a recommended breakpoint location just before a
    /// function's epilogue.
    epilogue_begin: bool,
    /// Discriminator distinguishing multiple blocks associated with the same
    /// source line.
    discriminator: u64,
    /// Resolved file entry for `file_index`, indexing into the owning
    /// [`LineTable::file_entries`].
    file_entry: Option<usize>,
}

struct LineTableIterator<'l, 'elf> {
    /// Mutably borrowed so DW_LNE_define_file can append to `file_entries`
    /// during iteration; the emitted entries reference files by index into it.
    line_table: &'l mut LineTable,
    /// The ELF owning the `.debug_line` bytes referenced by `line_table.data_range`.
    /// `LineTable` is stored owned inside `Dwarf`, so the iterator carries the
    /// `&Elf` instead, matching `RangeListIterator`.
    elf: &'elf Elf,
    // For the entire matrix entry to which it’s currently pointing
    current: LineTableEntry<'elf>,
    /// For the current state of the abstract machine registers
    registers: LineTableEntry<'elf>,
    /// A byte position inside the .debug_line section pointing to the data to parse next
    position: usize,
    /// Whether this iterator is responsible for appending DW_LNE_define_file
    /// entries to the table. Only the first iterator created for a table does so;
    /// later ones parse the opcode but leave `file_entries` untouched.
    should_load_files: bool,
}

// ===================================================================

// --- Dwarf ---

impl Dwarf {
    /// Parses the DWARF info for `elf`.
    ///
    /// Returns `Ok(None)` when the ELF has no `.debug_info` section (a stripped
    /// binary, or one built without debug info), and `Err` only when the section
    /// is present but cannot be parsed.
    pub fn new(elf: Rc<Elf>) -> Result<Option<Dwarf>> {
        let mut dwarf = Dwarf {
            elf: Rc::clone(&elf),
            compile_units: Vec::new(),
            line_tables: Vec::new(),
            function_index: HashMap::new(),
            abbrev_table_cache: RefCell::new(HashMap::new()),
        };
        dwarf.compile_units = match dwarf.build_compile_units()? {
            Some(compile_units) => compile_units,
            None => return Ok(None),
        };

        dwarf.line_tables = match dwarf.build_line_tables()? {
            Some(line_tables) => line_tables,
            None => return Ok(None),
        };
        // Build the function index eagerly. The walk only reads `compile_units`
        // and the abbrev cache, so the (empty) `function_index` is never observed
        // before it is assigned.
        dwarf.function_index = dwarf.build_function_index();
        Ok(Some(dwarf))
    }

    pub fn elf(&self) -> &Elf {
        &self.elf
    }

    pub fn compile_units(&self) -> &[CompileUnit] {
        &self.compile_units
    }

    /// The whole `.debug_info` section, resolved from the ELF on demand.
    fn debug_info(&self) -> &[u8] {
        self.elf
            .get_section_content_by_name(
                CStr::from_bytes_with_nul(b".debug_info\0").expect("nul-terminated"),
            )
            .expect("`.debug_info` was present at construction")
    }

    /// Resolves a CU's DIE bytes (header stripped) within the `.debug_info` section.
    fn cu_data(&self, cu_index: usize) -> &[u8] {
        let range = self.compile_units[cu_index].data_range.clone();
        &self.debug_info()[range]
    }

    fn get_abbrev_table(&self, offset: usize) -> Result<Rc<AbbrevTable>> {
        if let Some(table) = self.abbrev_table_cache.borrow().get(&offset) {
            return Ok(Rc::clone(table));
        }
        let table = Rc::new(parse_abbrev_table(&self.elf, offset)?);
        self.abbrev_table_cache
            .borrow_mut()
            .insert(offset, Rc::clone(&table));
        Ok(table)
    }

    pub fn root_of<'dw>(&'dw self, cu_index: usize) -> Result<Die<'dw>> {
        let table = self.get_abbrev_table(self.compile_units[cu_index].abbrev_offset)?;
        let mut cursor = Cursor::new(self.cu_data(cu_index));
        parse_die_raw(&mut cursor, self, cu_index, table)
    }

    pub fn compile_unit_containing_address(&self, address: FileAddress<'_>) -> Option<usize> {
        (0..self.compile_units.len()).find(|&cu_index| {
            self.root_of(cu_index)
                .expect("Failed to extract root DIE from compile unit")
                .contains(address)
        })
    }

    pub fn function_containing_address<'dw>(
        &'dw self,
        address: FileAddress<'_>,
    ) -> Option<Die<'dw>> {
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
            // Parse over the whole CU data (advancing the cursor to `offset`)
            // rather than a `[offset..]` sub-slice: the parsed DIE's
            // `attr_locations` must stay absolute within `cu_data` because
            // `Attr` accessors index back into the full slice.
            let mut cursor = Cursor::new(self.cu_data(cu_index));
            cursor.increment_cursor_by(offset);
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

    pub fn find_functions<'dw>(&'dw self, function_name: &str) -> Vec<Die<'dw>> {
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
                // Parse over the whole CU data (advancing the cursor to `offset`)
                // rather than a `[offset..]` sub-slice, so the DIE's
                // `attr_locations` stay absolute within `cu_data` — `Attr`
                // accessors index back into the full slice.
                let mut cursor = Cursor::new(self.cu_data(cu_index));
                cursor.increment_cursor_by(offset);
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

    /// Parses the compile units from the `.debug_info` section.
    ///
    /// Returns `Ok(None)` when the ELF has no `.debug_info` section.
    fn build_compile_units(&self) -> Result<Option<Vec<CompileUnit>>> {
        let debug_info_bytes = match self
            .elf
            .get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_info\0")?)
        {
            Some(debug_info_bytes) => debug_info_bytes,
            None => return Ok(None),
        };
        Ok(Some(parse_compile_units(debug_info_bytes)?))
    }

    fn build_line_tables(&self) -> Result<Option<Vec<Option<LineTable>>>> {
        assert!(!self.compile_units.is_empty());
        let debug_line_bytes = match self
            .elf
            .get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_line\0")?)
        {
            Some(debug_line_bytes) => debug_line_bytes,
            None => return Ok(None),
        };

        let line_tables = self
            .compile_units
            .iter()
            .enumerate()
            .map(|(cu_index, _compile_unit)| {
                self.build_line_table_for_compile_unit(cu_index, debug_line_bytes)
            })
            .collect::<Result<Vec<_>>>()?; // Will short circuit and return an error early if build_line_table_for_compile_unit fails even once

        assert!(line_tables.len() == self.compile_units.len());
        Ok(Some(line_tables))
    }

    fn cstr_to_pathbuf_unix(c_str: &CStr) -> PathBuf {
        let os_str =
            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(c_str.to_bytes());
        PathBuf::from(os_str) // Correct way to instantiate an owned PathBuf
    }

    fn build_line_table_for_compile_unit(
        &self,
        cu_index: usize,
        debug_line_bytes: &[u8],
    ) -> Result<Option<LineTable>> {
        let root_die_payload = match self.root_of(cu_index)? {
            Die::Null(_) => return Err(anyhow!("Expected non-null DIE")),
            Die::NonNull(die_payload) => die_payload,
        };

        let attr = match root_die_payload.get_attr(DwAt::StmtList as u64) {
            Some(attr) => attr,
            None => return Ok(None),
        };
        let section_offset = attr.as_section_offset()? as usize;

        let mut cursor = Cursor::new(&debug_line_bytes[section_offset..]);

        // unit_length (uint32_t) The byte size of the line number information for this compile unit,
        // not including the unit_length field itself.
        let size: usize = cursor.read_u32()? as usize;
        let end: usize = cursor.position() + size;

        if cursor.read_u16()? != 4 {
            return Err(anyhow!("Only DWARF 4 is supported"));
        }

        let _header_length = cursor.read_u32()?;

        let minimum_instruction_length = cursor.read_u8()?;
        if minimum_instruction_length != 1 {
            return Err(anyhow!("Invalid minimum instruction length"));
        }

        let maximum_operations_per_instruction = cursor.read_u8()?;
        if maximum_operations_per_instruction != 1 {
            return Err(anyhow!("Invalid maximum operations per instruction"));
        }

        let default_is_statement: bool = cursor.read_u8()? > 0;
        let line_base: i8 = cursor.read_i8()?;
        let line_range: u8 = cursor.read_u8()?;
        let opcode_base: u8 = cursor.read_u8()?;

        const EXPECTED_OPCODE_LENGTHS: &'static [u8; 12] = &[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];

        if (opcode_base as usize - 1) > EXPECTED_OPCODE_LENGTHS.len() {
            return Err(anyhow!("Invalid value for op_code_base"));
        }

        for i in 0..(opcode_base - 1) as usize {
            if cursor.read_u8()? != EXPECTED_OPCODE_LENGTHS[i] {
                return Err(anyhow!("Unexpected opcode length"));
            }
        }

        // Next we parse the include directories
        let compilation_dir = Self::cstr_to_pathbuf_unix(
            root_die_payload
                .get_attr(DwAt::CompDir as u64)
                .ok_or(anyhow!("Root does not contain DwAt::CompDir"))?
                .as_string()?,
        );

        // Read null-terminated directory entries until the empty string terminator,
        // resolving each relative path against the compilation directory.
        let include_directories =
            std::iter::from_fn(
                || match cursor.read_string().map(Self::cstr_to_pathbuf_unix) {
                    Ok(dir) if dir.is_empty() => None, // Terminate the iteration, we hit a null byte
                    other => Some(other),
                },
            )
            .map(|dir| {
                dir.map(|dir| {
                    if dir.is_absolute() {
                        dir
                    } else {
                        compilation_dir.join(dir)
                    }
                })
            })
            .collect::<Result<Vec<PathBuf>>>()?;

        // Read null-terminated file entries until the null-byte terminator.
        let file_entries = std::iter::from_fn(|| match cursor.peek() {
            0 => None, // Terminate the iteration, we hit the null byte
            _ => Some(Self::parse_line_table_file(
                &mut cursor,
                &compilation_dir,
                &include_directories,
            )),
        })
        .collect::<Result<Vec<FileEntry>>>()?;

        // Consume the null byte that terminates the file-name list; the cursor now
        // points at the first byte of the opcode stream. Cursor positions are
        // relative to `section_offset`, so shift by it to index the whole section.
        cursor.increment_cursor_by(1);
        let data_range = (section_offset + cursor.position())..(section_offset + end);

        Ok(Some(LineTable {
            data_range,
            default_is_statement,
            line_base,
            line_range,
            opcode_base,
            include_directories,
            comp_dir: compilation_dir,
            define_files_loaded: false,
            file_entries,
        }))
    }

    fn parse_line_table_file(
        cursor: &mut Cursor,
        compilation_dir: &Path,
        include_directories: &Vec<PathBuf>,
    ) -> Result<FileEntry> {
        let file_name = cursor.read_string()?;
        let dir_index = cursor.uleb128()? as usize;
        let modification_time = cursor.uleb128()? as usize;
        let file_length = cursor.uleb128()? as usize;

        let file_path: PathBuf = {
            let file_path = Self::cstr_to_pathbuf_unix(file_name);
            if !file_path.is_absolute() {
                if dir_index == 0 {
                    compilation_dir.join(file_path)
                } else {
                    include_directories[dir_index - 1].join(file_path)
                }
            } else {
                file_path
            }
        };

        Ok(FileEntry {
            path: file_path,
            modification_time,
            file_length,
        })
    }

    fn index_die(die: Die<'_>, index: &mut HashMap<String, Vec<IndexEntry>>) {
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

fn find_cu_containing(dwarf: &Dwarf, abs_offset: usize) -> Result<(usize, usize)> {
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

impl<'dw> Die<'dw> {
    pub fn children(&self) -> Option<DieChildrenIter<'dw>> {
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

    pub fn get_attr(&self, attr: u64) -> Option<Attr<'dw>> {
        let payload = match &self {
            Die::Null(_) => return None,
            Die::NonNull(die_payload) => die_payload,
        };
        payload.get_attr(attr)
    }

    pub fn low_pc(&self) -> Result<FileAddress<'dw>> {
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

    pub fn high_pc(&self) -> Result<FileAddress<'dw>> {
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
                elf_handle: attr.dwarf.elf(),
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
        if let Die::Null(_) = self {
            return None;
        }

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
            let referenced_die: Die<'dw> = attr
                .as_reference()
                .expect("Failed to get referenced DIE with DwAt::Specification");
            return referenced_die.name();
        }

        if let Some(attr) = self.get_attr(DwAt::AbstractOrigin as u64) {
            let referenced_die: Die<'dw> = attr
                .as_reference()
                .expect("Failed to get referenced DIE with DwAt::AbstractOrigin");
            return referenced_die.name();
        }
        return None;
    }
}

impl<'dw> DiePayload<'dw> {
    pub fn children(&self) -> DieChildrenIter<'dw> {
        DieChildrenIter {
            cu_index: self.cu_index,
            abbrev_table: Rc::clone(&self.abbrev_table),
            current_offset: self.next,
            done: !self.abbrev.has_children,
            dwarf: self.dwarf,
        }
    }

    pub fn get_attr(&self, attr: u64) -> Option<Attr<'dw>> {
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

impl<'dw> Iterator for DieChildrenIter<'dw> {
    type Item = Result<Die<'dw>>;

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

fn parse_die_raw<'dw>(
    cursor: &mut Cursor,
    dwarf: &'dw Dwarf,
    cu_index: usize,
    abbrev_table: Rc<AbbrevTable>,
) -> Result<Die<'dw>> {
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

impl<'dw> Attr<'dw> {
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

    pub fn as_address(&self) -> Result<FileAddress<'dw>> {
        if self.dw_form()? != DwForm::Addr {
            return Err(anyhow!("Invalid attr type. Expected DwForm::Addr"));
        }
        let mut cursor = Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
        let address = cursor.read_u64().context("Failed to extract u64")? as usize;
        Ok(FileAddress {
            elf_handle: self.dwarf.elf(),
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

    pub fn as_reference(&self) -> Result<Die<'dw>> {
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

    pub fn as_string(&self) -> Result<&'dw CStr> {
        let mut cursor: Cursor<'dw> =
            Cursor::new(&self.dwarf.cu_data(self.cu_index)[self.location_offset..]);
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

    pub fn as_range_list(&self) -> Result<RangeList<'dw>> {
        // Validate the section is present up front; the iterator resolves the
        // bytes lazily from this offset.
        debug_ranges_section(self.dwarf.elf())?;
        // Parse the offset stored at the current attribute position
        let offset = self.as_section_offset()? as usize;
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
                    elf_handle: self.dwarf.elf(),
                    address: 0usize,
                },
            }
        };
        Ok(RangeList {
            elf: self.dwarf.elf(),
            offset,
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
    parse_abbrev_table_from_section(section_buffer, offset)
}

/// Parses one abbreviation table out of the raw `.debug_abbrev` bytes, starting
/// at `offset`. Split out from [`parse_abbrev_table`] so the decoding can be
/// exercised without an [`Elf`].
fn parse_abbrev_table_from_section(section_buffer: &[u8], offset: usize) -> Result<AbbrevTable> {
    let mut cursor = Cursor::new(section_buffer);
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

/// Resolves the `.debug_ranges` section bytes.
fn debug_ranges_section(elf: &Elf) -> Result<&[u8]> {
    elf.get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_ranges\0")?)
        .ok_or_else(|| anyhow!("Failed to find .debug_ranges"))
}

impl<'elf> RangeList<'elf> {
    pub fn iter(&self) -> RangeListIterator<'elf> {
        RangeListIterator {
            elf: self.elf,
            offset: self.offset,
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

/// A concrete range-list entry decoded from `.debug_ranges`, with the effective
/// base address carried forward from any base-address selectors consumed.
struct RawRangeEntry {
    /// Effective base address after applying any base-address selectors.
    base: u64,
    /// Range start/end offsets, relative to `base`.
    low: u64,
    high: u64,
    /// Position just past this entry, relative to the start of the range list.
    next_position: usize,
}

/// Steps through a `.debug_ranges` range list and returns the next concrete entry.
///
/// `data` starts at the range list; `position` is the byte offset of the next
/// entry within it; `base` is the current base address. The section consists of
/// 8-byte (on x64) integer pairs of three kinds:
///   - regular entries: `low`/`high` offsets relative to the current base address,
///   - base-address selectors: a `u64::MAX` sentinel followed by the new base,
///   - an end-of-list indicator: two zero integers.
///
/// Selectors are applied and skipped; the returned `base` reflects them. Returns
/// `Ok(None)` at the end-of-list indicator.
fn next_raw_range_entry(
    data: &[u8],
    mut position: usize,
    mut base: u64,
) -> Result<Option<RawRangeEntry>> {
    const BASE_ADDRESS_FLAG: u64 = u64::MAX;
    let mut cursor = Cursor::new(&data[position..]);
    loop {
        let low = cursor
            .read_u64()
            .context("Failed to extract range-list entry low")?;
        let high = cursor
            .read_u64()
            .context("Failed to extract range-list entry high")?;
        if low == BASE_ADDRESS_FLAG {
            base = high;
        } else if low == 0 && high == 0 {
            return Ok(None);
        } else {
            position += cursor.position();
            return Ok(Some(RawRangeEntry {
                base,
                low,
                high,
                next_position: position,
            }));
        }
    }
}

impl<'elf> Iterator for RangeListIterator<'elf> {
    type Item = RangeListEntry<'elf>;

    fn next(&mut self) -> Option<Self::Item> {
        let debug_ranges = debug_ranges_section(self.elf).expect("Failed to find .debug_ranges");
        let data = &debug_ranges[self.offset..];
        let entry = next_raw_range_entry(data, self.position, self.base_address.address as u64)
            .expect("Failed to read range-list entry")?;
        self.base_address = FileAddress {
            elf_handle: self.elf,
            address: entry.base as usize,
        };
        self.position = entry.next_position;
        Some(RangeListEntry {
            low: self.base_address + entry.low as usize,
            high: self.base_address + entry.high as usize,
        })
    }
}

impl<'elf> PartialEq for LineTableEntry<'elf> {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.file_index == other.file_index
            && self.line == other.line
            && self.column == other.column
            && self.discriminator == other.discriminator
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}

impl<'elf> LineTableEntry<'elf> {
    /// The initial register state at the start of a line-number program, per the
    /// DWARF spec: address 0, file 1, line 1, everything else cleared. `is_stmt`
    /// is seeded from the line table's `default_is_statement`.
    fn reset(elf: &'elf Elf, default_is_stmt: bool) -> Self {
        LineTableEntry {
            address: FileAddress::new(elf, 0),
            file_index: 1,
            line: 1,
            column: 0,
            is_stmt: default_is_stmt,
            basic_block_start: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            discriminator: 0,
            file_entry: None,
        }
    }
}

impl LineTable {
    /// Iterates the rows of this line-number program.
    ///
    /// `elf` supplies the `.debug_line` bytes (via `data_range`) and anchors the
    /// `FileAddress` lifetime of the produced entries. `LineTable` is stored owned
    /// inside `Dwarf`, so it can't hold the `&Elf` itself; the caller threads it in
    /// here, mirroring `RangeList::iter`.
    fn iter<'l, 'elf>(&'l mut self, elf: &'elf Elf) -> LineTableIterator<'l, 'elf> {
        // Read the fields needed to seed the iterator before moving the mutable
        // borrow of `self` into `line_table`. The first iterator to run loads the
        // DW_LNE_define_file entries; subsequent iterators leave them in place.
        let default_is_statement = self.default_is_statement;
        let position = self.data_range.start;
        let should_load_files = !self.define_files_loaded;
        self.define_files_loaded = true;
        LineTableIterator {
            elf,
            current: LineTableEntry::reset(elf, default_is_statement),
            registers: LineTableEntry::reset(elf, default_is_statement),
            position,
            should_load_files,
            line_table: self,
        }
    }
}

/// Resolves the `.debug_line` section bytes.
fn debug_line_section(elf: &Elf) -> Result<&[u8]> {
    elf.get_section_content_by_name(CStr::from_bytes_with_nul(b".debug_line\0")?)
        .ok_or_else(|| anyhow!("Failed to find .debug_line"))
}

impl<'l, 'elf> LineTableIterator<'l, 'elf> {
    /// Decodes and applies the next opcode of the line-number program, advancing
    /// `position`. Returns `true` when the opcode emits a row into `current`.
    fn execute_instruction(&mut self) -> bool {
        let debug_line = debug_line_section(self.elf).expect("Failed to find .debug_line");
        // Cursor over this table's remaining opcode bytes: from the current
        // position up to the end of the table's slice of the section.
        let mut cursor = Cursor::new(&debug_line[self.position..self.line_table.data_range.end]);
        let opcode = cursor.read_u8().expect("Failed to read line-table opcode");
        let mut emitted = false;
        if opcode > 0 && opcode < self.line_table.opcode_base {
            // Handle standard opcode
            let opcode = DwLns::try_from(opcode).expect("Failed to convert opcode to DwLns type");
            match opcode {
                DwLns::Copy => {
                    self.current = self.registers.clone();
                    self.registers.basic_block_start = false;
                    self.registers.prologue_end = false;
                    self.registers.epilogue_begin = false;
                    self.registers.discriminator = 0;
                    emitted = true;
                }
                DwLns::AdvancePc => {
                    let offset = cursor.uleb128().expect("Failed to get PC offset") as usize;
                    self.registers.address = self.registers.address + offset;
                }
                DwLns::AdvanceLine => {
                    let offset = cursor.sleb128().expect("Failed to get line offset");
                    self.registers.line = (self.registers.line as i64 + offset) as u64;
                }
                DwLns::SetFile => {
                    self.registers.file_index = cursor.uleb128().expect("Failed to get file index");
                }
                DwLns::SetColumn => {
                    self.registers.column = cursor.uleb128().expect("Failed to get column");
                }
                DwLns::NegateStmt => {
                    self.registers.is_stmt = !self.registers.is_stmt;
                }
                DwLns::SetBasicBlock => {
                    self.registers.basic_block_start = true;
                }
                DwLns::ConstAddPc => {
                    // Advance the address by the amount a special opcode 255 would,
                    // without touching the line register.
                    let advance = (255 - self.line_table.opcode_base) as usize
                        / self.line_table.line_range as usize;
                    self.registers.address = self.registers.address + advance;
                }
                DwLns::FixedAdvancePc => {
                    let advance = cursor.read_u16().expect("Failed to get fixed PC advance");
                    self.registers.address = self.registers.address + advance as usize;
                }
                DwLns::SetPrologueEnd => {
                    self.registers.prologue_end = true;
                }
                DwLns::SetEpilogueBegin => {
                    self.registers.epilogue_begin = true;
                }
                DwLns::SetIsa => {
                    // The `isa` register is not modeled, so nothing is applied.
                    // DW_LNS_set_isa carries a ULEB128 operand that we don't consume
                    // here; if a producer ever emits it, the unread operand desyncs
                    // the cursor for the next opcode. Warn so it's noticed.
                    eprintln!(
                        "Warning: DW_LNS_set_isa encountered in .debug_line at offset {}; \
                         operand not consumed, subsequent opcodes may be misparsed",
                        self.position
                    );
                }
            }
        } else if opcode == 0 {
            // The length (sub-opcode byte plus operands) is read to advance the
            // cursor past it; each opcode below consumes its own operands.
            let _length = cursor
                .uleb128()
                .expect("Failed to get length of extended opcode");
            let extended_opcode =
                DwLne::try_from(cursor.read_u8().expect("Failed to read extended opcode"))
                    .expect("Found unexpected extended opcode");
            match extended_opcode {
                DwLne::EndSequence => {
                    // Mark the closing row, emit it, then reset the registers to
                    // their initial state for any following sequence.
                    self.registers.end_sequence = true;
                    self.current = self.registers.clone();
                    self.registers =
                        LineTableEntry::reset(self.elf, self.line_table.default_is_statement);
                    emitted = true;
                }
                DwLne::SetAddress => {
                    let address = cursor
                        .read_u64()
                        .expect("Failed to read set_address operand");
                    self.registers.address = FileAddress::new(self.elf, address as usize);
                }
                DwLne::DefineFile => {
                    // Parse the inline file definition (advancing the cursor past
                    // its operands regardless), resolving relative paths against
                    // the CU's compilation directory. Only the first iteration
                    // appends it; later ones leave `file_entries` untouched so
                    // re-iterating never duplicates entries.
                    let file = Dwarf::parse_line_table_file(
                        &mut cursor,
                        &self.line_table.comp_dir,
                        &self.line_table.include_directories,
                    )
                    .expect("Failed to parse DW_LNE_define_file entry");
                    if self.should_load_files {
                        self.line_table.file_entries.push(file);
                    }
                }
                DwLne::SetDiscriminator => {
                    self.registers.discriminator = cursor
                        .uleb128()
                        .expect("Failed to read set_discriminator operand");
                }
                DwLne::LoUser | DwLne::HiUser => {
                    panic!("Unexpected extended opcode");
                }
            }
        } else {
            // Special opcode
            assert!(opcode >= self.line_table.opcode_base);
            let adjusted_opcode = opcode - self.line_table.opcode_base;
            self.registers.address =
                self.registers.address + (adjusted_opcode / self.line_table.line_range) as usize;
            self.registers.line = self.registers.line
                + (self.line_table.line_base as u64
                    + (adjusted_opcode % self.line_table.line_range) as u64);
            self.current = self.registers.clone();
            self.registers.basic_block_start = false;
            self.registers.prologue_end = false;
            self.registers.epilogue_begin = false;
            self.registers.discriminator = 0;
            emitted = true;
        }
        // `cursor.position()` is relative to `self.position`, so advance by it to
        // keep `position` absolute within the `.debug_line` section.
        self.position += cursor.position();
        emitted
    }
}

impl<'l, 'elf> Iterator for LineTableIterator<'l, 'elf> {
    type Item = LineTableEntry<'elf>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.line_table.data_range.end {
            return None;
        }
        // Step through opcodes until one emits a row
        while !self.execute_instruction() {}
        let mut next = self.current.clone();
        next.file_entry = Some((self.current.file_index - 1) as usize);
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes one `.debug_ranges` integer pair (low, high) as little-endian bytes.
    fn pair(low: u64, high: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&low.to_le_bytes());
        v.extend_from_slice(&high.to_le_bytes());
        v
    }

    #[test]
    fn range_list_advances_across_multiple_entries() {
        let mut data = Vec::new();
        data.extend(pair(0x10, 0x20));
        data.extend(pair(0x30, 0x40));
        data.extend(pair(0, 0)); // end-of-list

        let e1 = next_raw_range_entry(&data, 0, 0).unwrap().unwrap();
        assert_eq!((e1.base, e1.low, e1.high), (0, 0x10, 0x20));
        assert_eq!(e1.next_position, 16);

        // Regression: the position must advance to the *second* entry rather than
        // re-reading the first (the old `self.position = cursor.position()` bug).
        let e2 = next_raw_range_entry(&data, e1.next_position, e1.base)
            .unwrap()
            .unwrap();
        assert_eq!((e2.base, e2.low, e2.high), (0, 0x30, 0x40));
        assert_eq!(e2.next_position, 32);

        assert!(
            next_raw_range_entry(&data, e2.next_position, e2.base)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn range_list_applies_base_address_selector() {
        let mut data = Vec::new();
        data.extend(pair(u64::MAX, 0x1000)); // base-address selector
        data.extend(pair(0x10, 0x20)); // offsets relative to the new base
        data.extend(pair(0, 0)); // end-of-list

        let e = next_raw_range_entry(&data, 0, 0).unwrap().unwrap();
        assert_eq!(e.base, 0x1000);
        assert_eq!((e.low, e.high), (0x10, 0x20));
        // Selector (16 bytes) + entry (16 bytes) consumed.
        assert_eq!(e.next_position, 32);

        assert!(
            next_raw_range_entry(&data, e.next_position, e.base)
                .unwrap()
                .is_none()
        );
    }

    // --- Compile-unit header parsing -----------------------------------------

    /// Encodes a DWARF32 CU header followed by `die_bytes`. `unit_length` is
    /// written verbatim so malformed-length cases can be exercised; use
    /// [`cu_bytes`] for a self-consistent header.
    fn cu_bytes_raw(
        unit_length: u32,
        version: u16,
        abbrev_offset: u32,
        address_size: u8,
        die_bytes: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&unit_length.to_le_bytes());
        v.extend_from_slice(&version.to_le_bytes());
        v.extend_from_slice(&abbrev_offset.to_le_bytes());
        v.push(address_size);
        v.extend_from_slice(die_bytes);
        v
    }

    /// A well-formed DWARF32 v4 header (version 4, 8-byte addresses) wrapping
    /// `die_bytes`, with a self-consistent `unit_length`.
    fn cu_bytes(abbrev_offset: u32, die_bytes: &[u8]) -> Vec<u8> {
        // unit_length counts everything after the length field itself:
        // version (2) + abbrev_offset (4) + address_size (1) + DIE bytes.
        let unit_length = (2 + 4 + 1 + die_bytes.len()) as u32;
        cu_bytes_raw(unit_length, 4, abbrev_offset, 8, die_bytes)
    }

    #[test]
    fn parse_compile_unit_reads_well_formed_header() {
        let die_bytes = [0xAA, 0xBB, 0xCC];
        let bytes = cu_bytes(0x1234, &die_bytes);
        let mut cursor = Cursor::new(&bytes);

        let cu = parse_compile_unit(&mut cursor).expect("valid CU header parses");
        assert_eq!(cu.abbrev_offset, 0x1234);
        assert_eq!(cu.debug_info_offset, 0);
        // data_range strips the header and covers only the DIE bytes.
        assert_eq!(cu.data_range, COMPILE_UNIT_HEADER_SIZE..bytes.len());
        assert_eq!(cu.data_range.len(), die_bytes.len());
        // The cursor is left just past the whole CU.
        assert_eq!(cursor.position(), bytes.len());
    }

    #[test]
    fn parse_compile_unit_rejects_dwarf64() {
        // A unit_length of 0xffffffff signals the (unsupported) 64-bit format.
        let bytes = cu_bytes_raw(0xffff_ffff, 4, 0, 8, &[]);
        let mut cursor = Cursor::new(&bytes);
        assert!(parse_compile_unit(&mut cursor).is_err());
    }

    #[test]
    fn parse_compile_unit_rejects_unsupported_version() {
        let die_bytes = [0u8; 2];
        let unit_length = (2 + 4 + 1 + die_bytes.len()) as u32;
        let bytes = cu_bytes_raw(unit_length, 5, 0, 8, &die_bytes); // version 5
        let mut cursor = Cursor::new(&bytes);
        assert!(parse_compile_unit(&mut cursor).is_err());
    }

    #[test]
    fn parse_compile_unit_rejects_non_8_byte_addresses() {
        let die_bytes = [0u8; 2];
        let unit_length = (2 + 4 + 1 + die_bytes.len()) as u32;
        let bytes = cu_bytes_raw(unit_length, 4, 0, 4, &die_bytes); // 4-byte addresses
        let mut cursor = Cursor::new(&bytes);
        assert!(parse_compile_unit(&mut cursor).is_err());
    }

    #[test]
    fn parse_compile_units_tracks_offsets_across_units() {
        // Two back-to-back CUs with 3- and 5-byte DIE bodies.
        let first = cu_bytes(0x10, &[1, 2, 3]);
        let second = cu_bytes(0x20, &[4, 5, 6, 7, 8]);
        let mut section = first.clone();
        section.extend_from_slice(&second);

        let cus = parse_compile_units(&section).expect("two CUs parse");
        assert_eq!(cus.len(), 2);

        assert_eq!(cus[0].debug_info_offset, 0);
        assert_eq!(cus[0].abbrev_offset, 0x10);
        assert_eq!(cus[0].data_range, COMPILE_UNIT_HEADER_SIZE..first.len());

        // The second CU's footprint starts exactly where the first ends, and its
        // data_range skips its own header.
        assert_eq!(cus[1].debug_info_offset, first.len());
        assert_eq!(cus[1].abbrev_offset, 0x20);
        let second_data_start = first.len() + COMPILE_UNIT_HEADER_SIZE;
        assert_eq!(cus[1].data_range, second_data_start..section.len());
    }

    // --- Abbreviation table parsing ------------------------------------------

    /// Unsigned LEB128 encoding of `value`.
    fn uleb(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    /// Encodes one abbreviation declaration: code, tag, children flag, and its
    /// (attr, form) specs terminated by the 0,0 pair.
    fn abbrev_decl(code: u64, tag: u64, has_children: bool, specs: &[(u64, u64)]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(uleb(code));
        v.extend(uleb(tag));
        v.push(if has_children { 1 } else { 0 });
        for &(attr, form) in specs {
            v.extend(uleb(attr));
            v.extend(uleb(form));
        }
        v.extend(uleb(0)); // attr terminator
        v.extend(uleb(0)); // form terminator
        v
    }

    #[test]
    fn parse_abbrev_table_round_trips_declarations() {
        let mut section = Vec::new();
        section.extend(abbrev_decl(
            1,
            DwTag::CompileUnit as u64,
            true,
            &[
                (DwAt::Name as u64, DwForm::Strp as u64),
                (DwAt::Language as u64, DwForm::Data1 as u64),
            ],
        ));
        section.extend(abbrev_decl(
            2,
            DwTag::BaseType as u64,
            false,
            &[(DwAt::ByteSize as u64, DwForm::Data1 as u64)],
        ));
        section.push(0); // table terminator (code 0)

        let table = parse_abbrev_table_from_section(&section, 0).expect("table parses");
        assert_eq!(table.len(), 2);

        let a1 = &table[&1];
        assert_eq!(a1.code, 1);
        assert_eq!(a1.tag, DwTag::CompileUnit as u64);
        assert!(a1.has_children);
        assert_eq!(a1.attr_specs.len(), 2);
        assert_eq!(a1.attr_specs[0].attr, DwAt::Name as u64);
        assert_eq!(a1.attr_specs[0].form, DwForm::Strp as u64);
        assert_eq!(a1.attr_specs[1].attr, DwAt::Language as u64);
        assert_eq!(a1.attr_specs[1].form, DwForm::Data1 as u64);

        let a2 = &table[&2];
        assert_eq!(a2.tag, DwTag::BaseType as u64);
        assert!(!a2.has_children);
        assert_eq!(a2.attr_specs.len(), 1);
    }

    #[test]
    fn parse_abbrev_table_honors_offset() {
        let mut section = vec![0xde, 0xad, 0xbe, 0xef]; // padding before the table
        let offset = section.len();
        section.extend(abbrev_decl(7, DwTag::Variable as u64, false, &[]));
        section.push(0); // table terminator

        let table = parse_abbrev_table_from_section(&section, offset).expect("table parses");
        assert_eq!(table.len(), 1);
        assert_eq!(table[&7].tag, DwTag::Variable as u64);
    }

    #[test]
    fn parse_abbrev_table_truncated_input_errors() {
        // A declaration code with no following tag byte: the stream ends mid-entry.
        let section = uleb(1);
        assert!(parse_abbrev_table_from_section(&section, 0).is_err());
    }

    // --- skip_children --------------------------------------------------------

    fn abbrev(code: u64, tag: u64, has_children: bool, specs: &[(u64, u64)]) -> Rc<Abbrev> {
        Rc::new(Abbrev {
            code,
            tag,
            has_children,
            attr_specs: specs
                .iter()
                .map(|&(attr, form)| AttrSpec { attr, form })
                .collect(),
        })
    }

    #[test]
    fn skip_children_walks_nested_dies() {
        // Abbrev 1: one Data1 attribute, has children. Abbrev 2: empty leaf.
        let mut table: AbbrevTable = HashMap::new();
        table.insert(
            1,
            abbrev(
                1,
                DwTag::LexicalBlock as u64,
                true,
                &[(DwAt::LowPc as u64, DwForm::Data1 as u64)],
            ),
        );
        table.insert(2, abbrev(2, DwTag::Variable as u64, false, &[]));

        // One abbrev-1 DIE (with its data byte) containing one abbrev-2 child, a
        // null closing those children, and a null closing the sibling list.
        let mut data = Vec::new();
        data.extend(uleb(1)); // abbrev 1
        data.push(0xFF); //      its Data1 attribute value
        data.extend(uleb(2)); // child: abbrev 2
        data.extend(uleb(0)); // end of abbrev-1's children
        data.extend(uleb(0)); // end of the sibling list

        let mut cursor = Cursor::new(&data);
        skip_children(&mut cursor, &table).expect("nested children are skipped");
        assert_eq!(cursor.position(), data.len());
    }

    #[test]
    fn skip_children_unknown_code_errors() {
        let table: AbbrevTable = HashMap::new(); // empty: every code is unknown
        let data = uleb(9);
        let mut cursor = Cursor::new(&data);
        assert!(skip_children(&mut cursor, &table).is_err());
    }

    #[test]
    fn skip_children_truncated_attribute_errors() {
        // Abbrev 1 promises a Data1 byte, but the stream ends right after the code.
        let mut table: AbbrevTable = HashMap::new();
        table.insert(
            1,
            abbrev(
                1,
                DwTag::Variable as u64,
                false,
                &[(DwAt::LowPc as u64, DwForm::Data1 as u64)],
            ),
        );
        let data = uleb(1); // code only, no attribute byte
        let mut cursor = Cursor::new(&data);
        assert!(skip_children(&mut cursor, &table).is_err());
    }
}
