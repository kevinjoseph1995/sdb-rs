use crate::elf::Elf;
use anyhow::{Context, Result, anyhow};
use std::{collections::HashMap, ffi::CStr};

pub struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

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

pub struct Dwarf<'a> {
    elf: &'a Elf,
    /// The .debug_abbrev section contains several abbreviation tables. Each compile
    /// unit in the .debug_info section uses exactly one abbreviation table, but different
    /// compile units may share the same table.
    /// Maps byte offsets to another map, of integers to abbreviation entries.
    abbrev_table: HashMap<u64, HashMap<u64 /* abbreviation code*/, Abbrev>>,
}

macro_rules! impl_read_int {
    ($($method:ident => $ty:ty),* $(,)?) => {
        impl<'a> Cursor<'a> {
            $(
                pub fn $method(&mut self) -> Result<$ty> {
                    self.read_bytes::<{ std::mem::size_of::<$ty>() }>()
                        .map(<$ty>::from_le_bytes)
                }
            )*
        }
    };
}

fn parse_abbrev_table(elf: &Elf, offset: usize) -> Result<HashMap<u64, Abbrev>> {
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

impl<'a> Dwarf<'a> {
    pub fn new(elf: &'a Elf) -> Dwarf<'a> {
        Dwarf {
            elf,
            abbrev_table: HashMap::new(),
        }
    }

    pub fn get_abbrev_table(&'a mut self, offset: usize) -> Result<&'a HashMap<u64, Abbrev>> {
        if !self.abbrev_table.contains_key(&(offset as u64)) {
            // Cache miss
            let table = parse_abbrev_table(self.elf, offset)?;
            self.abbrev_table.insert(offset as u64, table);
        }
        Ok(self.abbrev_table.get(&(offset as u64)).unwrap())
    }
}

impl<'a> Cursor<'a> {
    pub fn new<'b>(bytes: &'b [u8]) -> Cursor<'b> {
        Cursor { bytes, position: 0 }
    }

    fn increment_cursor_by(&mut self, n: usize) {
        self.position += n;
    }

    pub fn is_at_end(&self) -> bool {
        return self.position >= self.bytes.len();
    }

    fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.position + N;
        if end > self.bytes.len() {
            return Err(anyhow!("DWARF cursor error, reached end of stream"));
        }
        let bytes = self.bytes[self.position..end].try_into().unwrap();
        self.increment_cursor_by(N);
        Ok(bytes)
    }

    pub fn read_string(&mut self) -> Result<&CStr> {
        if self.is_at_end() {
            return Err(anyhow!(
                "DWARF cursor error, failed to read string already at the end of the stream"
            ));
        }
        let old_position = self.position;
        let null_byte_position: usize = match self.bytes[self.position..]
            .iter()
            .position(|byte| *byte == 0u8)
        {
            Some(pos) => pos,
            None => {
                return Err(anyhow!(
                    "DWARF curosor error, failed to find null terminator. Failed to parse string"
                ));
            }
        };
        self.increment_cursor_by(null_byte_position + 1);
        // SAFETY: We've already found our null-terminator at this point. No point in scanning through our stream again
        Ok(unsafe {
            CStr::from_bytes_with_nul_unchecked(
                &self.bytes[old_position..=old_position + null_byte_position],
            )
        })
    }

    /// Unsigned Little Endian Base 128
    pub fn uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            let value_bits = byte & 0b0111_1111;
            result |= (value_bits as u64) << shift;
            shift += 7;
            let has_more_bits = byte & 0b1000_0000 > 0;
            if !has_more_bits {
                break;
            }
        }
        Ok(result)
    }
    /// Little Endian Base 128
    pub fn sleb128(&mut self) -> Result<i64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        let mut byte: u8;
        loop {
            byte = self.read_u8()?;
            let value_bits = byte & 0b0111_1111;
            result |= (value_bits as u64) << shift;
            shift += 7;
            let has_more_bits = byte & 0b1000_0000 > 0;
            if !has_more_bits {
                break;
            }
        }
        if shift < std::mem::size_of_val(&result) * 8 && byte & 0b0100_0000 > 0 {
            result |= !0u64 << shift;
        }
        Ok(result as i64)
    }
}

impl_read_int! {
    read_u8  => u8,
    read_u16 => u16,
    read_u32 => u32,
    read_u64 => u64,
    read_i8  => i8,
    read_i16 => i16,
    read_i32 => i32,
    read_i64 => i64,
}
