use crate::dwarf_constants::DwForm;
use anyhow::{Result, anyhow};
use std::ffi::CStr;

pub struct Cursor<'a> {
    pub bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub fn new<'b>(bytes: &'b [u8]) -> Cursor<'b> {
        Cursor { bytes, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn increment_cursor_by(&mut self, n: usize) {
        self.position += n;
    }

    pub fn is_at_end(&self) -> bool {
        return self.position >= self.bytes.len();
    }

    pub fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
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

    #[rustfmt::skip]
    pub(crate) fn skip_form(&mut self, form: u64) -> Result<()> {
        let f = form as u8;
        if f == DwForm::FlagPresent as u8 {
            // zero bytes — implicit flag
        } else if f == DwForm::Data1 as u8
               || f == DwForm::Ref1 as u8
               || f == DwForm::Flag as u8 {
            self.increment_cursor_by(1);
        } else if f == DwForm::Data2 as u8
               || f == DwForm::Ref2 as u8 {
            self.increment_cursor_by(2);
        } else if f == DwForm::Data4 as u8
               || f == DwForm::Ref4 as u8
               || f == DwForm::RefAddr as u8
               || f == DwForm::SecOffset as u8
               || f == DwForm::Strp as u8 {
            self.increment_cursor_by(4);
        } else if f == DwForm::Data8 as u8
               || f == DwForm::Addr as u8 {
            self.increment_cursor_by(8);
        } else if f == DwForm::Sdata as u8 {
            self.sleb128()?;
        } else if f == DwForm::Udata as u8
               || f == DwForm::RefUdata as u8 {
            self.uleb128()?;
        } else if f == DwForm::Block1 as u8 {
            let len = self.read_u8()? as usize;
            self.increment_cursor_by(len);
        } else if f == DwForm::Block2 as u8 {
            let len = self.read_u16()? as usize;
            self.increment_cursor_by(len);
        } else if f == DwForm::Block4 as u8 {
            let len = self.read_u32()? as usize;
            self.increment_cursor_by(len);
        } else if f == DwForm::Block as u8
               || f == DwForm::Exprloc as u8 {
            let len = self.uleb128()? as usize;
            self.increment_cursor_by(len);
        } else if f == DwForm::String as u8 {
            self.read_string()?;
        } else if f == DwForm::Indirect as u8 {
            let actual_form = self.uleb128()?;
            self.skip_form(actual_form)?;
        } else {
            return Err(anyhow!("Unrecognized DWARF form: {:#x}", form));
        }
        Ok(())
    }
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
