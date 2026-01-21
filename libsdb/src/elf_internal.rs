// Intentionally not using a crate for this. This is more in line with how the book does it,
// and we can always refactor to use a crate later if we want to add more features.

use anyhow::{Context, Result};
use memmap::{Mmap, MmapOptions};
use std::{
    ffi::{CStr, CString},
    path::{Path, PathBuf},
};

use crate::address::{FileAddress, VirtAddress};

/*
ASCII diagram adapted from: Figure 11-1: The layout of an ELF file of Building a Debugger

                 +----------------------+
                 |      ELF Header      |
                 +----------------------+
                 |   Program Headers    |
+----------------+----------------------+----------------+
|  Linking view  |        Data          | Execution view |
|                |                      |                |
|  +----------+  |                      |  +----------+  |
|  | Section 1|  |                      |  | Segment 1 |  |
|  +----------+  |                      |  +----------+  |
|                |                      |                |
|  +----------+  |                      |  +----------+  |
|  | Section 2|  |                      |  | Segment 2 |  |
|  +----------+  |                      |  +----------+  |
|                |                      |                |
|  +----------+  |                      |  +----------+  |
|  | Section 3|  |                      |  | Segment 3 |  |
|  +----------+  |                      |  +----------+  |
|                |                      |                |
+----------------+----------------------+----------------+
                 |   Section Headers    |
                 +----------------------+
 */

#[repr(C)]
#[derive(Debug)]
pub struct Elf64_Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Section header
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    /// For sections that contain fixed-size entries, this field gives the size of each entry. Otherwise, it should be 0.
    pub sh_entsize: u64,
}

/// Symbol table entry
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

#[derive(Debug)]
struct RawAddressRange {
    // Inclusive start
    start: usize,
    //  Exclusive end
    end: usize,
}

impl PartialEq for RawAddressRange {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for RawAddressRange {}

impl PartialOrd for RawAddressRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawAddressRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

#[derive(Debug)]
pub struct Elf {
    path: PathBuf,
    file_handle: std::fs::File,
    mmap: Mmap,
    header: Elf64_Ehdr,
    section_headers: Vec<Elf64_Shdr>,
    /// A map from section names to their index in the `section_headers` vector, for quick lookup.
    section_map: std::collections::HashMap<CString, usize>,
    /// The symbol table entries parsed from the ELF file.
    symbol_table: Vec<Elf64_Sym>,
    /// A map from symbol names to their indices in the `symbol_table` vector, for quick lookup.
    symbol_name_map: std::collections::HashMap<CString, Vec<usize>>,
    symbol_address_range_map: std::collections::BTreeMap<RawAddressRange, usize>,
    pub load_bias: Option<VirtAddress>,
}

impl Elf {
    pub fn new(path: &Path) -> Result<Self> {
        let path_buf = path.to_path_buf();
        let file_size = std::fs::metadata(&path_buf)?.len();
        let file_handle = std::fs::File::open(&path_buf)?;
        // SAFETY: The file handle is valid and the file size is correct, so this should be "OK".
        let mmap = unsafe { MmapOptions::new().map(&file_handle) }?;

        const HEADER_SIZE: usize = std::mem::size_of::<Elf64_Ehdr>();
        if file_size < HEADER_SIZE as u64 {
            anyhow::bail!("File is too small to be a valid ELF file");
        }
        // Check the magic number to verify that this is an ELF file.
        if &mmap[..4] != [0x7F, b'E', b'L', b'F'] {
            anyhow::bail!(
                "File does not have the ELF magic number at the beginning. Found: {:02X?}",
                &mmap[..4]
            );
        }
        // SAFETY: We have verified that the file is large enough to contain an ELF header, so this should be "OK".
        let header = unsafe { std::ptr::read_unaligned(mmap.as_ptr() as *const Elf64_Ehdr) };
        let section_headers = Self::parse_section_headers(&mmap, &header)?;
        let section_map = Self::build_section_map(&mmap, &header, &section_headers)?;
        let symbol_table = Self::parse_symbol_table(&mmap, &section_map, &section_headers)?;
        let mut elf = Self {
            header,
            path: path_buf,
            file_handle,
            mmap,
            section_headers,
            section_map,
            symbol_table,
            symbol_name_map: std::collections::HashMap::new(),
            symbol_address_range_map: std::collections::BTreeMap::new(),
            load_bias: None,
        };
        let (symbol_name_map, symbol_address_range_map) =
            Self::build_symbol_name_map(&elf.symbol_table, &elf)?;
        elf.symbol_name_map = symbol_name_map;
        elf.symbol_address_range_map = symbol_address_range_map;
        Ok(elf)
    }

    fn build_symbol_name_map(
        symbol_table: &[Elf64_Sym],
        elf: &Elf,
    ) -> Result<(
        std::collections::HashMap<CString, Vec<usize>>,
        std::collections::BTreeMap<RawAddressRange, usize>,
    )> {
        let mut symbol_name_map: std::collections::HashMap<CString, Vec<usize>> =
            std::collections::HashMap::new();
        let mut symbol_address_range_map: std::collections::BTreeMap<RawAddressRange, usize> =
            std::collections::BTreeMap::new();
        for (index, symbol) in symbol_table.iter().enumerate() {
            //// symbol_name_map population
            let mangled_name_cstr = match elf.get_string(symbol.st_name as usize) {
                Some(n) => n,
                None => continue,
            };
            symbol_name_map
                .entry(mangled_name_cstr.to_owned())
                .or_insert_with(Vec::new)
                .push(index);
            if let Ok(mangled_name) = mangled_name_cstr.to_str() {
                if let Ok(rustc_demangled_name) = rustc_demangle::try_demangle(mangled_name) {
                    let demangled_cstring = CString::new(rustc_demangled_name.to_string())
                        .context("Failed to create CString from demangled Rust name")?;
                    symbol_name_map
                        .entry(demangled_cstring)
                        .or_insert_with(Vec::new)
                        .push(index);
                } else if let Ok(cpp_demangled_name) = cpp_demangle::Symbol::new(mangled_name) {
                    if let Ok(demangled_cstring) = cpp_demangled_name.demangle() {
                        symbol_name_map
                            .entry(
                                CString::new(demangled_cstring)
                                    .context("Failed to create CString from demangled C++ name")?,
                            )
                            .or_insert_with(Vec::new)
                            .push(index);
                    }
                }
            }

            //// symbol_address_range_map population
            // Note: #define ELF64_ST_TYPE(i)   ((i)&0xf) | See: https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
            let st_type: u8 = symbol.st_info & 0x0F;
            if (symbol.st_value != 0) && (symbol.st_name != 0) && (st_type != elf::abi::STT_TLS) {
                let address_range = RawAddressRange {
                    start: symbol.st_value as usize,
                    end: symbol.st_value.checked_add(symbol.st_size).ok_or_else(|| {
                        anyhow::anyhow!("Symbol size overflow for symbol at index {}", index)
                    })? as usize,
                };
                symbol_address_range_map.insert(address_range, index);
            }
        }
        Ok((symbol_name_map, symbol_address_range_map))
    }

    fn parse_symbol_table(
        mmaped_file: &Mmap,
        section_map: &std::collections::HashMap<CString, usize>,
        section_headers: &[Elf64_Shdr],
    ) -> Result<Vec<Elf64_Sym>> {
        let symbol_table_section_header = match Self::get_section_header_by_name_internal(
            section_map,
            section_headers,
            CStr::from_bytes_with_nul(b".symtab\0").unwrap(),
        )
        .or(Self::get_section_header_by_name_internal(
            section_map,
            section_headers,
            CStr::from_bytes_with_nul(b".dynsym\0").unwrap(),
        )) {
            Some(header) => header,
            None => return Ok(Vec::new()), // No symbol table found, so we return an empty vector.
        };

        if symbol_table_section_header.sh_offset + symbol_table_section_header.sh_size
            > mmaped_file.len() as u64
        {
            anyhow::bail!(
                "Symbol table section exceeds file size (offset: {}, size: {})",
                symbol_table_section_header.sh_offset,
                symbol_table_section_header.sh_size
            );
        }
        const SYMBOL_TABLE_ENTRY_SIZE: usize = std::mem::size_of::<Elf64_Sym>();
        assert!(
            symbol_table_section_header.sh_entsize as usize == SYMBOL_TABLE_ENTRY_SIZE,
            "Expected symbol table entry size to be {}, but got {}",
            SYMBOL_TABLE_ENTRY_SIZE,
            symbol_table_section_header.sh_entsize
        );

        let number_of_entries = symbol_table_section_header
            .sh_size
            .checked_div(symbol_table_section_header.sh_entsize)
            .expect("symbol_table_section_header.sh_entsize must be non-zero");
        let mut symbol_table: Vec<Elf64_Sym> = Vec::with_capacity(number_of_entries as usize);

        for i in 0..number_of_entries {
            let entry_offset = symbol_table_section_header
                .sh_offset
                .checked_add(
                    i.checked_mul(SYMBOL_TABLE_ENTRY_SIZE as u64)
                        .expect("Entry offset calculation overflow"),
                )
                .expect("Entry offset calculation overflow");
            symbol_table.push(
                // SAFETY: We have verified that the entry is within the bounds of the file, so this should be "OK".
                unsafe {
                    std::ptr::read_unaligned(
                        mmaped_file.as_ptr().add(entry_offset as usize) as *const Elf64_Sym
                    )
                },
            );
        }

        Ok(symbol_table)
    }

    fn notify_loaded(&mut self, load_bias: VirtAddress) {
        self.load_bias = Some(load_bias);
    }

    pub fn get_section_start_address<'a>(&'a self, section_name: &CStr) -> Option<FileAddress<'a>> {
        if let Some(section) = self.get_section_header_by_name(section_name) {
            Some(FileAddress::new(&self, section.sh_addr as usize))
        } else {
            None
        }
    }

    pub fn get_section_containing_file_address(
        &self,
        file_address: &FileAddress,
    ) -> Option<&Elf64_Shdr> {
        let elf_handle_pointer = file_address.elf_handle as *const Elf;
        let self_ptr = self as *const Elf;
        if self_ptr != elf_handle_pointer {
            return None;
        }
        self.section_headers.iter().find(|sh_header| {
            sh_header.sh_addr as usize <= file_address.address
                && file_address.address < (sh_header.sh_addr + sh_header.sh_size) as usize
        })
    }

    pub fn get_symbols_with_name(&self, name: &CStr) -> Vec<&Elf64_Sym> {
        self.symbol_name_map
            .get(name)
            .map_or(Vec::new(), |indices| {
                indices
                    .iter()
                    .filter_map(|&index| self.symbol_table.get(index))
                    .collect()
            })
    }

    pub fn get_symbol_at_address(&self, file_address: FileAddress) -> Option<&Elf64_Sym> {
        let address_range = RawAddressRange {
            start: file_address.address,
            end: 0usize, // end is not used for lookup in this case
        };
        self.symbol_address_range_map
            .get(&address_range)
            .and_then(|&index| self.symbol_table.get(index))
    }

    pub fn get_symbol_containing_address(&self, file_address: FileAddress) -> Option<&Elf64_Sym> {
        let query = RawAddressRange {
            start: file_address.address,
            end: 0,
        };

        // Find the symbol with the largest start address <= query address
        let mut candidate_range = self.symbol_address_range_map.range(..=query);
        loop {
            if let Some((r, index)) = candidate_range.next_back() {
                if file_address.address < r.end {
                    return Some(&self.symbol_table[*index]);
                }
            } else {
                break;
            }
        }
        None
    }

    pub fn get_section_containing_virtual_address(
        &self,
        virt_address: &VirtAddress,
    ) -> Option<&Elf64_Shdr> {
        self.section_headers.iter().find(|sh_header| {
            let load_bias = self
                .load_bias
                .expect("It is expected that load_bias is set");
            sh_header.sh_addr as usize + load_bias.address <= virt_address.address
                && virt_address.address
                    < (load_bias.address + (sh_header.sh_addr + sh_header.sh_size) as usize)
        })
    }

    fn build_section_map(
        mmaped_file: &Mmap,
        header: &Elf64_Ehdr,
        section_headers: &[Elf64_Shdr],
    ) -> Result<std::collections::HashMap<CString, usize>> {
        let mut section_map = std::collections::HashMap::new();
        for (index, section_header) in section_headers.iter().enumerate() {
            let name = Self::section_name_internal(
                mmaped_file,
                section_headers,
                header,
                section_header.sh_name as usize,
            )?;
            if let Some(existing_index) = section_map.insert(name.to_owned(), index) {
                anyhow::bail!(
                    "Duplicate section name found: {} (indices {} and {})",
                    name.to_string_lossy(),
                    existing_index,
                    index
                );
            }
        }
        Ok(section_map)
    }

    fn get_section_header_by_name_internal<'a>(
        section_map: &std::collections::HashMap<CString, usize>,
        section_headers: &'a [Elf64_Shdr],
        name: &CStr,
    ) -> Option<&'a Elf64_Shdr> {
        if let Some(&index) = section_map.get(name) {
            Some(
                section_headers
                    .get(index)
                    .expect("Section index out of bounds"),
            )
        } else {
            None
        }
    }

    pub fn get_section_header_by_name(&self, name: &CStr) -> Option<&Elf64_Shdr> {
        Self::get_section_header_by_name_internal(&self.section_map, &self.section_headers, name)
    }

    fn get_section_content_by_name(&self, section_name: &CStr) -> Option<&[u8]> {
        if let Some(section_header) = self.get_section_header_by_name(section_name) {
            let offset = section_header.sh_offset as usize;
            let size = section_header.sh_size as usize;
            if offset
                .checked_add(size)
                .map_or(true, |end| end > self.mmap.len())
            {
                panic!(
                    "Section '{}' content exceeds file size (offset: {}, size: {})",
                    section_name.to_string_lossy(),
                    offset,
                    size
                );
            }
            Some(&self.mmap[offset..offset + size])
        } else {
            // Section not found.
            None
        }
    }

    fn section_name(&self, sh_name: usize) -> Result<&CStr> {
        Self::section_name_internal(&self.mmap, &self.section_headers, &self.header, sh_name)
    }

    fn get_string(&self, string_offset: usize) -> Option<&CStr> {
        if let Some(section_header) = self
            .get_section_header_by_name(CStr::from_bytes_with_nul(b".strtab\0").unwrap())
            .or(self.get_section_header_by_name(CStr::from_bytes_with_nul(b".dynstr\0").unwrap()))
        {
            let string_table_offset = section_header.sh_offset as usize;
            let string_table_size = section_header.sh_size as usize;
            let table_end = string_table_offset
                .checked_add(string_table_size)
                .expect("String table size overflows");
            if table_end > self.mmap.len() {
                panic!(
                    "String table exceeds file size (offset: {}, size: {})",
                    string_table_offset, string_table_size
                );
            }
            if string_offset >= string_table_size {
                panic!(
                    "String offset {} is out of bounds for string table of size {}",
                    string_offset, string_table_size
                );
            }
            let table = &self.mmap[string_table_offset..table_end];
            let null_pos = table[string_offset..]
                .iter()
                .position(|&byte| byte == 0)
                .expect("String is not null-terminated");
            let cstr = std::ffi::CStr::from_bytes_with_nul(
                &table[string_offset..string_offset + null_pos + 1],
            )
            .expect("Invalid string bytes");
            Some(cstr)
        } else {
            // No string table found, so we can't resolve the string.
            return None;
        }
    }

    fn section_name_internal<'a>(
        mmaped_file: &'a Mmap,
        section_headers: &[Elf64_Shdr],
        elf_header: &Elf64_Ehdr,
        sh_name: usize,
    ) -> Result<&'a CStr> {
        let shstrndx = elf_header.e_shstrndx as usize;
        if shstrndx >= section_headers.len() {
            anyhow::bail!("Section name string table index out of range");
        }
        let string_table_section_header = &section_headers[shstrndx];
        let string_table_offset = string_table_section_header.sh_offset as usize;
        let string_table_size = string_table_section_header.sh_size as usize;
        let table_end = string_table_offset
            .checked_add(string_table_size)
            .ok_or_else(|| anyhow::anyhow!("Section name string table overflows"))?;
        if table_end > mmaped_file.len() {
            anyhow::bail!("Section name string table exceeds file size");
        }
        if sh_name >= string_table_size {
            anyhow::bail!("Section name offset out of range");
        }
        let table = &mmaped_file[string_table_offset..table_end];
        let name_bytes = &table[sh_name..];
        let nul_pos = name_bytes
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| anyhow::anyhow!("Section name is not null-terminated"))?;
        Ok(std::ffi::CStr::from_bytes_with_nul(&name_bytes[..=nul_pos])
            .map_err(|err| anyhow::anyhow!("Invalid section name bytes: {}", err))?)
    }

    fn parse_section_headers(mmaped_file: &Mmap, header: &Elf64_Ehdr) -> Result<Vec<Elf64_Shdr>> {
        const SECTION_HEADER_SIZE: usize = std::mem::size_of::<Elf64_Shdr>();
        let file_len = mmaped_file.len();
        if header.e_shoff > usize::MAX as u64 {
            anyhow::bail!("Section headers offset exceeds addressable memory");
        }
        let num_of_sections = {
            if header.e_shnum == 0 && header.e_shentsize != 0 {
                // Special case for when the file has 0xff00 or more sections.
                // In this case, the actual number of sections is stored in the sh_size field of the first section header.
                let section_headers_offset = header.e_shoff as usize;
                if section_headers_offset
                    .checked_add(SECTION_HEADER_SIZE)
                    .map_or(true, |end| end > file_len)
                {
                    anyhow::bail!("Section header exceeds file size");
                }
                let first_section_header_ptr = unsafe {
                    mmaped_file.as_ptr().add(section_headers_offset) as *const Elf64_Shdr
                };
                // SAFETY: We have verified that the section header is within
                // the bounds of the file, so this should be "OK".
                let first_section_header =
                    unsafe { std::ptr::read_unaligned(first_section_header_ptr) };
                if first_section_header.sh_size > usize::MAX as u64 {
                    anyhow::bail!("Section count exceeds addressable memory");
                }
                first_section_header.sh_size as usize
            } else {
                header.e_shnum as usize
            }
        };

        let section_headers_offset = header.e_shoff as usize;
        let section_headers_size = num_of_sections
            .checked_mul(SECTION_HEADER_SIZE)
            .ok_or_else(|| anyhow::anyhow!("Section headers size overflows"))?;
        if section_headers_offset
            .checked_add(section_headers_size)
            .map_or(true, |end| end > file_len)
        {
            anyhow::bail!("Section headers exceed file size");
        }

        let section_headers_ptr =
            unsafe { mmaped_file.as_ptr().add(section_headers_offset) as *const Elf64_Shdr };

        let mut section_headers = Vec::with_capacity(num_of_sections);
        unsafe {
            // SAFETY: The mmap is validated to cover the entire section header table,
            // and Elf64_Shdr is a plain data structure, so a byte-wise copy is OK.
            std::ptr::copy_nonoverlapping(
                section_headers_ptr as *const u8,
                section_headers.as_mut_ptr() as *mut u8,
                section_headers_size,
            );
            section_headers.set_len(num_of_sections);
        }
        Ok(section_headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_creation() {
        // Pick a test binary that is known to be an ELF file.
        let test_binary_path = PathBuf::from(
            test_binary::build_test_binary("anti_debugger", &PathBuf::from_iter(["..", "tools"]))
                .expect("Failed to build test binary"),
        );
        // Use the `elf` crate to parse the same file and compare the results to our implementation.
        let file_content_slice =
            std::fs::read(&test_binary_path).expect("Failed to read test binary");
        let reference_elf =
            elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(file_content_slice.as_slice())
                .expect("Failed to parse ELF file");

        let elf = Elf::new(&test_binary_path).expect("Failed to create ELF object");
        assert_eq!(elf.path, test_binary_path);
        assert!(elf.mmap.len() > 0);
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Header validation: Compare the ELF header from our implementation to the one from the `elf` crate.
        // Not all fields are compared here, just some basic sanity checks to ensure that we are parsing the header correctly.
        let reference_header = reference_elf.ehdr;
        assert_eq!(reference_header.e_ehsize, elf.header.e_ehsize);
        assert_eq!(reference_header.e_phentsize, elf.header.e_phentsize);
        assert_eq!(reference_header.e_phnum, elf.header.e_phnum);
        assert_eq!(reference_header.e_shentsize, elf.header.e_shentsize);
        assert_eq!(reference_header.e_shnum, elf.header.e_shnum);
        assert_eq!(reference_header.e_shoff, elf.header.e_shoff);
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Section header validation: Compare the section headers from our implementation to the ones from the `elf` crate.
        let section_headers = reference_elf
            .section_headers()
            .expect("Failed to get section headers from ELF file");
        assert_eq!(section_headers.len(), elf.section_headers.len());

        let section_name_string_table = reference_elf
            .section_data_as_strtab(
                &section_headers
                    .get(reference_header.e_shstrndx as usize)
                    .expect("Failed to get section header string table"),
            )
            .expect("Failed to get section name string table");

        for section_header in section_headers {
            let matching_section_header = elf
                .section_headers
                .iter()
                .find(|sh| sh.sh_name == section_header.sh_name)
                .expect("Could not find matching section header");
            assert_eq!(matching_section_header.sh_type, section_header.sh_type);
            assert_eq!(matching_section_header.sh_flags, section_header.sh_flags);
            assert_eq!(matching_section_header.sh_addr, section_header.sh_addr);
            assert_eq!(matching_section_header.sh_offset, section_header.sh_offset);
            assert_eq!(matching_section_header.sh_size, section_header.sh_size);
            assert_eq!(matching_section_header.sh_link, section_header.sh_link);
            assert_eq!(matching_section_header.sh_info, section_header.sh_info);
            assert_eq!(
                matching_section_header.sh_addralign,
                section_header.sh_addralign
            );
            assert_eq!(
                matching_section_header.sh_entsize,
                section_header.sh_entsize
            );
            // Validate that the section name is correctly parsed from the string table.
            let expected_name = section_name_string_table
                .get(section_header.sh_name as usize)
                .expect("Failed to get section name from string table");
            let actual_name = elf
                .section_name(section_header.sh_name as usize)
                .expect("Failed to get section name")
                .to_str()
                .expect("Invalid UTF-8 in section name");
            assert_eq!(expected_name, actual_name);
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    }

    #[test]
    fn test_symbol_table_parsing() {
        // Pick a test binary that is known to be an ELF file.
        let test_binary_path = PathBuf::from(
            test_binary::build_test_binary("anti_debugger", &PathBuf::from_iter(["..", "tools"]))
                .expect("Failed to build test binary"),
        );
        // Use the `elf` crate to parse the same file and compare the results to our implementation.
        let file_content_slice =
            std::fs::read(&test_binary_path).expect("Failed to read test binary");
        let reference_elf =
            elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(file_content_slice.as_slice())
                .expect("Failed to parse ELF file");

        let elf = Elf::new(&test_binary_path).expect("Failed to create ELF object");

        // Get symbol table from reference implementation
        let (reference_symtab, reference_strtab) = reference_elf
            .symbol_table()
            .expect("Failed to get symbol table from reference ELF")
            .expect("No symbol table found in reference ELF");

        // Our implementation should have parsed the same number of symbols
        assert_eq!(
            reference_symtab.len(),
            elf.symbol_table.len(),
            "Symbol table length mismatch"
        );

        // Compare each symbol entry
        for (index, reference_sym) in reference_symtab.iter().enumerate() {
            let our_sym = &elf.symbol_table[index];

            assert_eq!(
                our_sym.st_name, reference_sym.st_name,
                "Symbol {} st_name mismatch",
                index
            );
            assert_eq!(
                our_sym.st_info, reference_sym.st_info,
                "Symbol {} st_info mismatch",
                index
            );
            assert_eq!(
                our_sym.st_other, reference_sym.st_other,
                "Symbol {} st_other mismatch",
                index
            );
            assert_eq!(
                our_sym.st_shndx, reference_sym.st_shndx,
                "Symbol {} st_shndx mismatch",
                index
            );
            assert_eq!(
                our_sym.st_value, reference_sym.st_value,
                "Symbol {} st_value mismatch",
                index
            );
            assert_eq!(
                our_sym.st_size, reference_sym.st_size,
                "Symbol {} st_size mismatch",
                index
            );

            // Also verify we can resolve symbol names correctly if st_name is non-zero
            if reference_sym.st_name != 0 {
                let expected_name = reference_strtab
                    .get(reference_sym.st_name as usize)
                    .expect("Failed to get symbol name from reference string table");
                let actual_name = elf
                    .get_string(reference_sym.st_name as usize)
                    .expect("Failed to get symbol name from our implementation");
                assert_eq!(
                    expected_name,
                    actual_name.to_str().expect("Invalid UTF-8 in symbol name"),
                    "Symbol {} name mismatch",
                    index
                );
                let symbols_with_name = elf.get_symbols_with_name(actual_name);
                assert!(
                    symbols_with_name
                        .iter()
                        .any(|&s| s.st_value == our_sym.st_value),
                    "Failed to find symbol by name for symbol {}",
                    index
                );
                // If this symbol has a address, verify it is in the address range map
                if reference_sym.st_value != 0
                    && reference_sym.st_size != 0
                    && reference_sym.st_symtype() != elf::abi::STT_TLS
                {
                    let file_address = FileAddress::new(&elf, reference_sym.st_value as usize);
                    let symbol_at_address = elf
                        .get_symbol_at_address(file_address)
                        .expect("Failed to get symbol at address");
                    assert_eq!(
                        symbol_at_address.st_value, our_sym.st_value,
                        "Symbol at address mismatch for symbol {}",
                        index
                    );
                    let symbol_containing_address = elf
                        .get_symbol_containing_address(file_address)
                        .expect("Failed to get symbol containing address");
                    assert_eq!(
                        symbol_containing_address.st_value, our_sym.st_value,
                        "Symbol containing address mismatch for symbol {}",
                        index
                    );
                    let file_address_in_range = FileAddress::new(
                        &elf,
                        reference_sym
                            .st_value
                            .checked_add(reference_sym.st_size / 2)
                            .expect("Address overflow") as usize,
                    );
                    let symbol_containing_address = elf
                        .get_symbol_containing_address(file_address_in_range)
                        .expect("Failed to get symbol containing address in range");
                    assert!(
                        (symbol_containing_address.st_value as usize)
                            <= file_address_in_range.address
                    );
                    if symbol_containing_address.st_size > 0 {
                        assert!(
                            (symbol_containing_address.st_value as usize
                                + symbol_containing_address.st_size as usize)
                                > file_address_in_range.address,
                            "Symbol containing address in range mismatch for. {} <= {}| st_vale={} st_size={}",
                            symbol_containing_address.st_value + symbol_containing_address.st_size,
                            file_address_in_range.address,
                            symbol_containing_address.st_value,
                            symbol_containing_address.st_size
                        );
                    }
                }
            }
        }
    }
}
