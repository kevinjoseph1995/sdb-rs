// Intentionally not using a crate for this. This is more in line with how the book does it,
// and we can always refactor to use a crate later if we want to add more features.

use anyhow::Result;
use memmap::{Mmap, MmapOptions};
use std::path::{Path, PathBuf};

#[repr(C)]
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

struct Elf {
    path: PathBuf,
    file_handle: std::fs::File,
    mmap: Mmap,
    header: Elf64_Ehdr,
    section_headers: Vec<Elf64_Shdr>,
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
        Ok(Self {
            header,
            path: path_buf,
            file_handle,
            mmap,
            section_headers,
        })
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
        let elf = Elf::new(&test_binary_path).expect("Failed to create ELF object");
        assert_eq!(elf.path, test_binary_path);
        assert!(elf.mmap.len() > 0);
        assert_eq!(elf.header.e_ident[..4], [0x7F, b'E', b'L', b'F']);

        let file_data = std::fs::read(test_binary_path).expect("Could not read file.");

        let elf_file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(file_data.as_slice())
            .expect("Failed to parse ELF file");
        let section_headers = elf_file
            .section_headers()
            .expect("Failed to get section headers from ELF file");
        assert_eq!(section_headers.len(), elf.section_headers.len());
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
        }
    }
}
