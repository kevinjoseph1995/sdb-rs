#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use libsdb::cursor::Cursor;

#[derive(Arbitrary, Debug)]
enum Op {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Uleb128,
    Sleb128,
    String,
    Skip(u8),
    Peek,
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    bytes: &'a [u8],
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    let mut cursor = Cursor::new(input.bytes);
    for op in input.ops {
        match op {
            Op::U8 => drop(cursor.read_u8()),
            Op::U16 => drop(cursor.read_u16()),
            Op::U32 => drop(cursor.read_u32()),
            Op::U64 => drop(cursor.read_u64()),
            Op::I8 => drop(cursor.read_i8()),
            Op::I16 => drop(cursor.read_i16()),
            Op::I32 => drop(cursor.read_i32()),
            Op::I64 => drop(cursor.read_i64()),
            Op::Uleb128 => drop(cursor.uleb128()),
            Op::Sleb128 => drop(cursor.sleb128()),
            Op::String => drop(cursor.read_string()),
            Op::Skip(n) => cursor.increment_cursor_by(n as usize),
            // peek indexes without a bounds check, so only call it when in range.
            Op::Peek => {
                if !cursor.is_at_end() {
                    cursor.peek();
                }
            }
        }
    }
});
