// Intentionally not using a crate for this. This is more in line with how the book does it,
// and we can always refactor to use a crate later if we want to add more features.

use anyhow::Result;
use memmap::{Mmap, MmapOptions};
use std::path::{Path, PathBuf};

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
    pub sh_entsize: u64,
}

#[derive(Debug)]
pub struct Elf {
    path: PathBuf,
    file_handle: std::fs::File,
    mmap: Mmap,
    header: Elf64_Ehdr,
    section_headers: Vec<Elf64_Shdr>,
    /// A map from section names to their index in the `section_headers` vector, for quick lookup.
    section_map: std::collections::HashMap<String, usize>,
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
        Ok(Self {
            header,
            path: path_buf,
            file_handle,
            mmap,
            section_headers,
            section_map,
        })
    }

    fn build_section_map(
        mmaped_file: &Mmap,
        header: &Elf64_Ehdr,
        section_headers: &[Elf64_Shdr],
    ) -> Result<std::collections::HashMap<String, usize>> {
        let mut section_map = std::collections::HashMap::new();
        for (index, section_header) in section_headers.iter().enumerate() {
            let name = Self::section_name_internal(
                mmaped_file,
                section_headers,
                header,
                section_header.sh_name as usize,
            )?;
            if let Some(existing_index) = section_map.insert(name.to_string(), index) {
                anyhow::bail!(
                    "Duplicate section name found: {} (indices {} and {})",
                    name,
                    existing_index,
                    index
                );
            }
        }
        Ok(section_map)
    }

    fn get_section_header_by_name(&self, name: &str) -> Option<&Elf64_Shdr> {
        if let Some(&index) = self.section_map.get(name) {
            Some(
                self.section_headers
                    .get(index)
                    .expect("Section index out of bounds"),
            )
        } else {
            None
        }
    }

    fn get_section_content_by_name(&self, section_name: &str) -> Option<&[u8]> {
        if let Some(section_header) = self.get_section_header_by_name(section_name) {
            let offset = section_header.sh_offset as usize;
            let size = section_header.sh_size as usize;
            if offset
                .checked_add(size)
                .map_or(true, |end| end > self.mmap.len())
            {
                panic!(
                    "Section '{}' content exceeds file size (offset: {}, size: {})",
                    section_name, offset, size
                );
            }
            Some(&self.mmap[offset..offset + size])
        } else {
            // Section not found.
            None
        }
    }

    fn section_name(&self, sh_name: usize) -> Result<&str> {
        Self::section_name_internal(&self.mmap, &self.section_headers, &self.header, sh_name)
    }

    fn get_string(&self, string_offset: usize) -> Option<&str> {
        if let Some(section_header) = self
            .get_section_header_by_name(".strtab")
            .or(self.get_section_header_by_name(".dynstr"))
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
            .expect("Invalid string bytes (not null-terminated)");
            Some(cstr.to_str().expect("Invalid UTF-8 in string table"))
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
    ) -> Result<&'a str> {
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
        let cstr = std::ffi::CStr::from_bytes_with_nul(&name_bytes[..=nul_pos])
            .map_err(|err| anyhow::anyhow!("Invalid section name bytes: {}", err))?;
        Ok(cstr
            .to_str()
            .map_err(|err| anyhow::anyhow!("Invalid UTF-8 in section name: {}", err))?)
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
                .expect("Failed to get section name");
            assert_eq!(expected_name, actual_name);
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    }
}
