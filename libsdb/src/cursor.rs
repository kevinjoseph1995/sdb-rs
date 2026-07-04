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

    pub fn peek(&self) -> u8 {
        return self.bytes[self.position];
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

    pub fn read_string(&mut self) -> Result<&'a CStr> {
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

    pub(crate) fn skip_form(&mut self, form: u64) -> Result<()> {
        let dw_form = u8::try_from(form)
            .ok()
            .and_then(|f| DwForm::try_from(f).ok())
            .ok_or_else(|| anyhow!("Unrecognized DWARF form: {:#x}", form))?;
        match dw_form {
            DwForm::FlagPresent => {} // zero bytes — implicit flag
            DwForm::Data1 | DwForm::Ref1 | DwForm::Flag => self.increment_cursor_by(1),
            DwForm::Data2 | DwForm::Ref2 => self.increment_cursor_by(2),
            DwForm::Data4 | DwForm::Ref4 | DwForm::RefAddr | DwForm::SecOffset | DwForm::Strp => {
                self.increment_cursor_by(4)
            }
            DwForm::Data8 | DwForm::Addr | DwForm::Ref8 | DwForm::RefSig8 => {
                self.increment_cursor_by(8)
            }
            DwForm::Sdata => {
                self.sleb128()?;
            }
            DwForm::Udata | DwForm::RefUdata => {
                self.uleb128()?;
            }
            DwForm::Block1 => {
                let len = self.read_u8()? as usize;
                self.increment_cursor_by(len);
            }
            DwForm::Block2 => {
                let len = self.read_u16()? as usize;
                self.increment_cursor_by(len);
            }
            DwForm::Block4 => {
                let len = self.read_u32()? as usize;
                self.increment_cursor_by(len);
            }
            DwForm::Block | DwForm::Exprloc => {
                let len = self.uleb128()? as usize;
                self.increment_cursor_by(len);
            }
            DwForm::String => {
                self.read_string()?;
            }
            DwForm::Indirect => {
                let actual_form = self.uleb128()?;
                self.skip_form(actual_form)?;
            }
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

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    // uleb128 tests
    #[test]
    fn uleb128_zero() {
        let mut cursor = Cursor::new(&[0x00]);
        assert_eq!(cursor.uleb128().unwrap(), 0);
    }

    #[test]
    fn uleb128_single_byte() {
        // Values 0–127 encode as a single byte with the high bit clear.
        let mut cursor = Cursor::new(&[0x7F]);
        assert_eq!(cursor.uleb128().unwrap(), 127);
    }

    #[test]
    fn uleb128_two_bytes() {
        // 128 encodes as [0x80, 0x01]: low 7 bits = 0, next 7 bits = 1.
        let mut cursor = Cursor::new(&[0x80, 0x01]);
        assert_eq!(cursor.uleb128().unwrap(), 128);
    }

    #[test]
    fn uleb128_three_bytes() {
        // 624_485 is the canonical example from the DWARF spec.
        // Encoded as [0xE5, 0x8E, 0x26].
        let mut cursor = Cursor::new(&[0xE5, 0x8E, 0x26]);
        assert_eq!(cursor.uleb128().unwrap(), 624_485);
    }

    #[test]
    fn uleb128_max_u64() {
        // u64::MAX encoded as ten bytes (each carrying 7 bits, all 1s).
        let bytes: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let mut cursor = Cursor::new(bytes);
        assert_eq!(cursor.uleb128().unwrap(), u64::MAX);
    }

    #[test]
    fn uleb128_advances_cursor() {
        // After reading one uleb128 value the cursor should be positioned at the next byte.
        let mut cursor = Cursor::new(&[0x01, 0x02]);
        assert_eq!(cursor.uleb128().unwrap(), 1);
        assert_eq!(cursor.uleb128().unwrap(), 2);
    }

    #[test]
    fn uleb128_empty_returns_error() {
        let mut cursor = Cursor::new(&[]);
        assert!(cursor.uleb128().is_err());
    }

    // sleb128 tests

    #[test]
    fn sleb128_zero() {
        let mut cursor = Cursor::new(&[0x00]);
        assert_eq!(cursor.sleb128().unwrap(), 0);
    }

    #[test]
    fn sleb128_positive_single_byte() {
        // 63 fits in 7 bits and has the sign bit clear → single byte.
        let mut cursor = Cursor::new(&[63]);
        assert_eq!(cursor.sleb128().unwrap(), 63);
    }

    #[test]
    fn sleb128_negative_single_byte() {
        // -1: all bits set in the 7-bit value (0x7F) with the high continuation bit clear.
        let mut cursor = Cursor::new(&[0x7F]);
        assert_eq!(cursor.sleb128().unwrap(), -1);
    }

    #[test]
    fn sleb128_negative_two_bytes() {
        // -128 encodes as [0x80, 0x7F].
        let mut cursor = Cursor::new(&[0x80, 0x7F]);
        assert_eq!(cursor.sleb128().unwrap(), -128);
    }

    #[test]
    fn sleb128_positive_two_bytes() {
        // 128 encodes as [0x80, 0x00] for unsigned, but sleb128 of [0x80, 0x00] is 128
        // because the sign bit (bit 6) of the final byte (0x00) is clear.
        let mut cursor = Cursor::new(&[0x80, 0x01]);
        assert_eq!(cursor.sleb128().unwrap(), 128);
    }

    #[test]
    fn sleb128_large_negative() {
        // -123_456 encoded via the DWARF sleb128 algorithm.
        // -123_456 in two's complement (64-bit) = 0xFFFF_FFFF_FFFE_1E40
        // Working out the encoding:
        //   byte 0: (-123456 & 0x7F) | 0x80 = (0x40) | 0x80 = 0xC0, shift >>7 → -965
        //   byte 1: (-965 & 0x7F) | 0x80 = (0x7B) | 0x80 = 0xFB, shift >>7 → -8 (not done, has more)
        // Let's just use known-good bytes: leb128 crate / manual calculation.
        // -123456 = 0xFFFFFFFFFFFE1E40
        // Encoding (little-endian, 7 bits per byte, continuation bit):
        //   0xC0 | 0x80 → 0xC0 (7 lsb of -123456 = 0x40, more bytes follow → 0xC0)
        //   next 7 bits: (-123456 >> 7) = -965; 0x7B | 0x80 → 0xFB
        //   next 7 bits: (-965 >> 7) = -8;      0x78 | 0x80 → 0xF8
        //   next 7 bits: (-8 >> 7) = -1;        0x7F — sign bit set, no more bytes needed
        let bytes: &[u8] = &[0xC0, 0xBB, 0x78];
        let mut cursor = Cursor::new(bytes);
        assert_eq!(cursor.sleb128().unwrap(), -123_456);
    }

    #[test]
    fn sleb128_advances_cursor() {
        // Encoding of -1 followed by encoding of 1.
        let mut cursor = Cursor::new(&[0x7F, 0x01]);
        assert_eq!(cursor.sleb128().unwrap(), -1);
        assert_eq!(cursor.sleb128().unwrap(), 1);
    }

    #[test]
    fn sleb128_i64_min() {
        // i64::MIN = -2^63. Encoding: 9 continuation bytes (0x80, value bits all zero)
        // followed by 0x7F (bit 0 survives the shift to bit 63, setting the MSB).
        let bytes: &[u8] = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
        let mut cursor = Cursor::new(bytes);
        assert_eq!(cursor.sleb128().unwrap(), i64::MIN);
    }

    #[test]
    fn sleb128_empty_returns_error() {
        let mut cursor = Cursor::new(&[]);
        assert!(cursor.sleb128().is_err());
    }
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

    // The following tests stress the slice bounds of the `unsafe`
    // `CStr::from_bytes_with_nul_unchecked` call in `read_string`. They are
    // designed to surface off-by-one errors in the inclusive range
    // `old_position..=old_position + null_byte_position` under Miri.

    #[test]
    fn read_string_empty() {
        // A lone null terminator: null_byte_position == 0, so the unsafe slice
        // is exactly the single byte `b"\0"`.
        let mut cursor = Cursor::new(b"\0");
        assert_eq!(
            cursor
                .read_string()
                .expect("Failed to extract empty string"),
            &CString::from_vec_with_nul(b"\0".to_vec()).unwrap()
        );
        assert!(cursor.is_at_end());
    }

    #[test]
    fn read_string_terminator_at_buffer_end() {
        // The null terminator is the final byte of the buffer, so the unsafe
        // slice's inclusive upper bound must be exactly the last valid index.
        // An off-by-one here would read one past the end.
        let mut cursor = Cursor::new(b"ABC\0");
        assert_eq!(
            cursor.read_string().expect("Failed to extract \"ABC\""),
            &CString::from_vec_with_nul(b"ABC\0".to_vec()).unwrap()
        );
        assert!(cursor.is_at_end());
    }

    #[test]
    fn read_string_leaves_cursor_mid_buffer() {
        // Reading a string from the middle of a buffer must produce a slice
        // bounded to that string and leave the cursor pointing at the byte
        // after its terminator (not at the end).
        let mut cursor = Cursor::new(b"hi\0\x2a");
        assert_eq!(
            cursor.read_string().expect("Failed to extract \"hi\""),
            &CString::from_vec_with_nul(b"hi\0".to_vec()).unwrap()
        );
        assert!(!cursor.is_at_end());
        assert_eq!(cursor.read_u8().unwrap(), 0x2a);
        assert!(cursor.is_at_end());
    }

    #[test]
    fn read_string_missing_terminator_errors() {
        // No null terminator: read_string must return an error and never reach
        // the unsafe block.
        let mut cursor = Cursor::new(b"no terminator");
        assert!(cursor.read_string().is_err());
    }
}
