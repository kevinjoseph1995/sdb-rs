use anyhow::{Result, anyhow};
use std::ffi::CStr;

pub struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_cursor_integer_extraction() {
        let input_bytes = {
            let mut bytes = Vec::<u8>::new();
            bytes.push(0u8);
            bytes.extend_from_slice(&(-666i16).to_le_bytes());
            bytes.extend_from_slice(&(666u32).to_le_bytes());
            bytes.extend_from_slice(&(666u64).to_le_bytes());
            bytes
        };

        let mut cursor = Cursor::new(&input_bytes);
        assert_eq!(cursor.read_u8().expect("Expected 0u8"), 0u8);
        assert_eq!(cursor.read_i16().expect("Expected -666i16"), -666i16);
        assert_eq!(cursor.read_u32().expect("Expected 666u32"), 666u32);
        assert_eq!(cursor.read_u64().expect("Expected 666u64"), 666u64);
        assert!(cursor.is_at_end());
    }

    #[test]
    fn test_string_extraction() {
        let input_bytes = {
            let mut bytes = Vec::<u8>::new();
            bytes.extend_from_slice(b"Hello\0");
            bytes.extend_from_slice(b"World\0");
            bytes.extend_from_slice(b"QWERTY\0");
            bytes
        };
        let mut cursor = Cursor::new(&input_bytes);
        assert_eq!(
            cursor.read_string().expect("Failed to extract \"Hello\""),
            &CString::from_vec_with_nul(b"Hello\0".to_vec()).unwrap()
        );
        assert_eq!(
            cursor.read_string().expect("Failed to extract \"World\""),
            &CString::from_vec_with_nul(b"World\0".to_vec()).unwrap()
        );
        assert_eq!(
            cursor.read_string().expect("Failed to extract \"Hello\""),
            &CString::from_vec_with_nul(b"QWERTY\0".to_vec()).unwrap()
        );
        assert!(cursor.is_at_end());
    }
}
