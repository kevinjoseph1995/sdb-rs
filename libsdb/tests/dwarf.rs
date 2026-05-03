use std::ffi::CString;

use libsdb::dwarf::Cursor;

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
