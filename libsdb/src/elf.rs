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

struct Elf {
    header: Elf64_Ehdr,
    path: PathBuf,
    file_size: u64,
    file_handle: std::fs::File,
    mmap: Mmap,
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
        Ok(Self {
            header,
            path: path_buf,
            file_size,
            file_handle,
            mmap,
        })
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
        assert!(elf.file_size > 0);
        assert_eq!(elf.header.e_ident[..4], [0x7F, b'E', b'L', b'F']);
    }
}
