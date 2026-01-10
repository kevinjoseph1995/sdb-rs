use std::fmt::Display;

use anyhow::Result;

use crate::elf::Elf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtAddress {
    pub address: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FileAddress<'a> {
    pub elf_handle: &'a Elf,
    pub address: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FileOffset<'a> {
    pub elf_handle: &'a Elf,
    pub offset: usize,
}

impl VirtAddress {
    pub fn new(address: usize) -> Self {
        VirtAddress { address }
    }

    pub fn get(self) -> usize {
        self.address
    }

    /// Returns the next page boundary address after this address.
    /// Example 4095 -> 4096
    /// Example 4096 -> 8192
    /// Example 8192 -> 12288
    /// Example 0 -> 4096
    pub fn next_page_boundary(&self) -> Self {
        const PAGE_SIZE: usize = 0x1000; // Assume 4 KiB page size
        VirtAddress {
            address: (self.address + PAGE_SIZE) & !0xFFF,
        }
    }

    pub fn to_file_address<'a>(&self, elf: &'a Elf) -> Option<FileAddress<'a>> {
        if let Some(_section) = elf.get_section_containing_virtual_address(&self) {
            let load_bias = elf.load_bias.expect("load_bias is expected to be set");
            Some(FileAddress::new(elf, self.address - load_bias.address))
        } else {
            None
        }
    }
}

impl std::ops::Add<VirtAddress> for VirtAddress {
    type Output = Self;

    fn add(self, rhs: VirtAddress) -> Self::Output {
        VirtAddress::new(self.address + rhs.address)
    }
}

impl std::ops::Add<usize> for VirtAddress {
    type Output = VirtAddress;

    fn add(self, rhs: usize) -> Self::Output {
        VirtAddress::new(self.address + rhs)
    }
}

impl std::ops::Sub<VirtAddress> for VirtAddress {
    type Output = Self;

    fn sub(self, rhs: VirtAddress) -> Self::Output {
        VirtAddress::new(self.address - rhs.address)
    }
}

impl PartialOrd for VirtAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl Display for VirtAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.address)
    }
}

impl From<usize> for VirtAddress {
    fn from(address: usize) -> Self {
        VirtAddress::new(address)
    }
}

impl Into<usize> for VirtAddress {
    fn into(self) -> usize {
        self.address
    }
}

impl<'a> FileAddress<'a> {
    pub fn new(elf_handle: &'a Elf, address: usize) -> FileAddress<'a> {
        FileAddress {
            elf_handle,
            address,
        }
    }

    pub fn get(self) -> usize {
        self.address
    }

    pub fn to_virt_address(&self) -> Option<VirtAddress> {
        if let Some(_section) = self.elf_handle.get_section_containing_file_address(&self) {
            let load_bias = self
                .elf_handle
                .load_bias
                .expect("load_bias expected to be set");
            Some(VirtAddress::new(self.address + load_bias.address))
        } else {
            None
        }
    }
}

impl<'a> std::ops::Add<FileAddress<'a>> for FileAddress<'a> {
    type Output = Self;

    fn add(self, rhs: FileAddress<'a>) -> Self::Output {
        FileAddress::new(self.elf_handle, self.address + rhs.address)
    }
}

impl<'a> std::ops::Add<usize> for FileAddress<'a> {
    type Output = FileAddress<'a>;

    fn add(self, rhs: usize) -> Self::Output {
        FileAddress::new(self.elf_handle, self.address + rhs)
    }
}

impl<'a> std::ops::Sub<FileAddress<'a>> for FileAddress<'a> {
    type Output = Self;

    fn sub(self, rhs: FileAddress<'a>) -> Self::Output {
        FileAddress::new(self.elf_handle, self.address - rhs.address)
    }
}

impl<'a> PartialEq for FileAddress<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl<'a> PartialOrd for FileAddress<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl<'a> Display for FileAddress<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.address)
    }
}

impl<'a> Into<usize> for FileAddress<'a> {
    fn into(self) -> usize {
        self.address
    }
}
