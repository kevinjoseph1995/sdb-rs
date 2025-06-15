/////////////////////////////////////////
use std::{fmt::Display, mem::zeroed};
/////////////////////////////////////////
use anyhow::{Context, Result, anyhow};
use extended::Extended;
use nix::libc::size_t;
/////////////////////////////////////////

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterType {
    General,
    SubGeneral, // e.g. x86 segment registers
    FloatingPoint,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterFormat {
    UnsignedInt,
    DoubleFloat,
    LongDouble,
    Vector,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterId {
    rax,
    rdx,
    rcx,
    rbx,
    rsi,
    rdi,
    rbp,
    rsp,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
    rip,
    eflags,
    cs,
    fs,
    gs,
    ss,
    ds,
    es,
    orig_rax,
    eax,
    edx,
    ecx,
    ebx,
    esi,
    edi,
    ebp,
    esp,
    r8d,
    r9d,
    r10d,
    r11d,
    r12d,
    r13d,
    r14d,
    r15d,
    ax,
    dx,
    cx,
    bx,
    si,
    di,
    bp,
    sp,
    r8w,
    r9w,
    r10w,
    r11w,
    r12w,
    r13w,
    r14w,
    r15w,
    ah,
    dh,
    ch,
    bh,
    al,
    dl,
    cl,
    bl,
    sil,
    dil,
    bpl,
    spl,
    r8b,
    r9b,
    r10b,
    r11b,
    r12b,
    r13b,
    r14b,
    r15b,
    fcw,
    fsw,
    ftw,
    fop,
    frip,
    frdp,
    mxcsr,
    mxcsrmask,
    st(u32),
    mm(u32),
    xmm(u32),
    dr(u32),
}

pub struct RegisterInfo {
    pub id: RegisterId,
    pub name: &'static str,
    pub dwarf_id: i32,
    pub size: size_t,
    pub offset: size_t,
    pub reg_type: RegisterType,
    pub reg_format: RegisterFormat,
}

macro_rules! gpr_offset {
    ($reg:ident) => {
        core::mem::offset_of!(libc::user, regs)
            + core::mem::offset_of!(libc::user_regs_struct, $reg)
    };
}

macro_rules! fpr_offset {
    ($reg:ident) => {
        core::mem::offset_of!(libc::user, i387)
            + core::mem::offset_of!(libc::user_fpregs_struct, $reg)
    };
}

macro_rules! fpr_size {
    ($reg:ident) => {{
        let object: libc::user_fpregs_struct = unsafe { core::mem::zeroed() };
        let size = core::mem::size_of_val(&object.$reg);
        size as size_t
    }};
}

macro_rules! dr_offset {
    ($number:expr) => {
        core::mem::offset_of!(libc::user, u_debugreg) + $number * 8
    };
}

macro_rules! define_gpr_64 {
    ($reg:ident, $dwarf_id:expr) => {
        RegisterInfo {
            id: RegisterId::$reg,
            name: stringify!($reg),
            dwarf_id: $dwarf_id,
            size: 8,
            offset: gpr_offset!($reg),
            reg_type: RegisterType::General,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

macro_rules! define_gpr_32 {
    ($reg:ident, $super:ident) => {
        RegisterInfo {
            id: RegisterId::$reg,
            name: stringify!($reg),
            dwarf_id: -1,
            size: 4,
            offset: gpr_offset!($super),
            reg_type: RegisterType::SubGeneral,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

macro_rules! define_gpr_16 {
    ($reg:ident, $super:ident) => {
        RegisterInfo {
            id: RegisterId::$reg,
            name: stringify!($reg),
            dwarf_id: -1,
            size: 2,
            offset: gpr_offset!($super),
            reg_type: RegisterType::SubGeneral,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

macro_rules! define_gpr_8h {
    ($reg:ident, $super:ident) => {
        RegisterInfo {
            id: RegisterId::$reg,
            name: stringify!($reg),
            dwarf_id: -1,
            size: 1,
            offset: gpr_offset!($super) + 1,
            reg_type: RegisterType::SubGeneral,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

macro_rules! define_gpr_8l {
    ($reg:ident, $super:ident) => {
        RegisterInfo {
            id: RegisterId::$reg,
            name: stringify!($reg),
            dwarf_id: -1,
            size: 1,
            offset: gpr_offset!($super),
            reg_type: RegisterType::SubGeneral,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

macro_rules! define_fpr {
    ($reg:ident, $dwarf_id:expr, $user_name:ident) => {
        RegisterInfo {
            id: RegisterId::$reg,
            name: stringify!($reg),
            dwarf_id: $dwarf_id,
            size: fpr_size!($user_name),
            offset: fpr_offset!($user_name),
            reg_type: RegisterType::FloatingPoint,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

macro_rules! define_fp_st {
    ($number:expr) => {
        RegisterInfo {
            id: RegisterId::st($number),
            name: concat!("st", stringify!($number)),
            dwarf_id: 33 + $number,
            size: 16,
            offset: fpr_offset!(st_space) + $number * 16,
            reg_type: RegisterType::FloatingPoint,
            reg_format: RegisterFormat::LongDouble,
        }
    };
}

macro_rules! define_fp_mm {
    ($number:expr) => {
        RegisterInfo {
            id: RegisterId::mm($number),
            name: concat!("mm", stringify!($number)),
            dwarf_id: 41 + $number,
            size: 8,
            offset: fpr_offset!(st_space) + $number * 16,
            reg_type: RegisterType::FloatingPoint,
            reg_format: RegisterFormat::Vector,
        }
    };
}

macro_rules! define_fp_xmm {
    ($number:expr) => {
        RegisterInfo {
            id: RegisterId::xmm($number),
            name: concat!("xmm", stringify!($number)),
            dwarf_id: 17 + $number,
            size: 16,
            offset: fpr_offset!(xmm_space) + $number * 16,
            reg_type: RegisterType::FloatingPoint,
            reg_format: RegisterFormat::Vector,
        }
    };
}

macro_rules! define_dr {
    ($number:expr) => {
        RegisterInfo {
            id: RegisterId::dr($number),
            name: concat!("dr", stringify!($number)),
            dwarf_id: -1,
            size: 8,
            offset: dr_offset!($number),
            reg_type: RegisterType::Debug,
            reg_format: RegisterFormat::UnsignedInt,
        }
    };
}

pub const REGISTER_INFO_TABLE: &[RegisterInfo] = &[
    ////////////////////////////// 64-bit registers //////////////////////////////
    define_gpr_64!(rax, 0),
    define_gpr_64!(rdx, 1),
    define_gpr_64!(rcx, 2),
    define_gpr_64!(rbx, 3),
    define_gpr_64!(rsi, 4),
    define_gpr_64!(rdi, 5),
    define_gpr_64!(rbp, 6),
    define_gpr_64!(rsp, 7),
    define_gpr_64!(r8, 8),
    define_gpr_64!(r9, 9),
    define_gpr_64!(r10, 10),
    define_gpr_64!(r11, 11),
    define_gpr_64!(r12, 12),
    define_gpr_64!(r13, 13),
    define_gpr_64!(r14, 14),
    define_gpr_64!(r15, 15),
    define_gpr_64!(rip, 16),
    define_gpr_64!(eflags, 49),
    define_gpr_64!(cs, 51),
    define_gpr_64!(fs, 54),
    define_gpr_64!(gs, 55),
    define_gpr_64!(ss, 52),
    define_gpr_64!(ds, 53),
    define_gpr_64!(es, 50),
    define_gpr_64!(orig_rax, -1),
    ////////////////////////////// 32-bit registers //////////////////////////////
    // The 32-bit registers are defined as sub-registers of the 64-bit ones.
    define_gpr_32!(eax, rax),
    define_gpr_32!(edx, rdx),
    define_gpr_32!(ecx, rcx),
    define_gpr_32!(ebx, rbx),
    define_gpr_32!(esi, rsi),
    define_gpr_32!(edi, rdi),
    define_gpr_32!(ebp, rbp),
    define_gpr_32!(esp, rsp),
    define_gpr_32!(r8d, r8),
    define_gpr_32!(r9d, r9),
    define_gpr_32!(r10d, r10),
    define_gpr_32!(r11d, r11),
    define_gpr_32!(r12d, r12),
    define_gpr_32!(r13d, r13),
    define_gpr_32!(r14d, r14),
    define_gpr_32!(r15d, r15),
    ////////////////////////////// 16-bit registers //////////////////////////////
    // The 16-bit registers are defined as sub-registers of the 64-bit ones.
    define_gpr_16!(ax, rax),
    define_gpr_16!(dx, rdx),
    define_gpr_16!(cx, rcx),
    define_gpr_16!(bx, rbx),
    define_gpr_16!(si, rsi),
    define_gpr_16!(di, rdi),
    define_gpr_16!(bp, rbp),
    define_gpr_16!(sp, rsp),
    define_gpr_16!(r8w, r8),
    define_gpr_16!(r9w, r9),
    define_gpr_16!(r10w, r10),
    define_gpr_16!(r11w, r11),
    define_gpr_16!(r12w, r12),
    define_gpr_16!(r13w, r13),
    define_gpr_16!(r14w, r14),
    define_gpr_16!(r15w, r15),
    ////////////////////////////// 8-bit registers //////////////////////////////
    // 8-bit high registers are defined as sub-registers of the 64-bit ones.
    define_gpr_8h!(ah, rax),
    define_gpr_8h!(dh, rdx),
    define_gpr_8h!(ch, rcx),
    define_gpr_8h!(bh, rbx),
    // 8-bit low registers are defined as sub-registers of the 64-bit ones.
    define_gpr_8l!(al, rax),
    define_gpr_8l!(dl, rdx),
    define_gpr_8l!(cl, rcx),
    define_gpr_8l!(bl, rbx),
    define_gpr_8l!(sil, rsi),
    define_gpr_8l!(dil, rdi),
    define_gpr_8l!(bpl, rbp),
    define_gpr_8l!(spl, rsp),
    define_gpr_8l!(r8b, r8),
    define_gpr_8l!(r9b, r9),
    define_gpr_8l!(r10b, r10),
    define_gpr_8l!(r11b, r11),
    define_gpr_8l!(r12b, r12),
    define_gpr_8l!(r13b, r13),
    define_gpr_8l!(r14b, r14),
    define_gpr_8l!(r15b, r15),
    ////////////////////////////// Floating Point Registers //////////////////////
    define_fpr!(fcw, 65, cwd),
    define_fpr!(fsw, 66, swd),
    define_fpr!(ftw, -1, ftw),
    define_fpr!(fop, -1, fop),
    define_fpr!(frip, -1, rip),
    define_fpr!(frdp, -1, rdp),
    define_fpr!(mxcsr, 64, mxcsr),
    define_fpr!(mxcsrmask, -1, mxcr_mask),
    /////////////////////////////////////////////////////////////////////////////
    define_fp_st!(0),
    define_fp_st!(1),
    define_fp_st!(2),
    define_fp_st!(3),
    define_fp_st!(4),
    define_fp_st!(5),
    define_fp_st!(6),
    define_fp_st!(7),
    /////////////////////////////////////////////////////////////////////////////
    define_fp_mm!(0),
    define_fp_mm!(1),
    define_fp_mm!(2),
    define_fp_mm!(3),
    define_fp_mm!(4),
    define_fp_mm!(5),
    define_fp_mm!(6),
    define_fp_mm!(7),
    /////////////////////////////////////////////////////////////////////////////
    define_fp_xmm!(0),
    define_fp_xmm!(1),
    define_fp_xmm!(2),
    define_fp_xmm!(3),
    define_fp_xmm!(4),
    define_fp_xmm!(5),
    define_fp_xmm!(6),
    define_fp_xmm!(7),
    define_fp_xmm!(8),
    define_fp_xmm!(9),
    define_fp_xmm!(10),
    define_fp_xmm!(11),
    define_fp_xmm!(12),
    define_fp_xmm!(13),
    define_fp_xmm!(14),
    define_fp_xmm!(15),
    /////////////////////////////////////////////////////////////////////////////
    ////////////////////////////// Debug Registers //////////////////////////////
    define_dr!(0),
    define_dr!(1),
    define_dr!(2),
    define_dr!(3),
    define_dr!(4),
    define_dr!(5),
    define_dr!(6),
    define_dr!(7),
];

const _: () = assert!(REGISTER_INFO_TABLE.len() == 125);

pub fn get_register_info(id: RegisterId) -> Option<&'static RegisterInfo> {
    REGISTER_INFO_TABLE.iter().find(|&reg| reg.id == id)
}

pub fn get_register_info_by_name(name: &str) -> Option<&'static RegisterInfo> {
    REGISTER_INFO_TABLE.iter().find(|&reg| reg.name == name)
}

pub fn get_register_info_by_dwarf_id(dwarf_id: i32) -> Option<&'static RegisterInfo> {
    REGISTER_INFO_TABLE
        .iter()
        .find(|&reg| reg.dwarf_id == dwarf_id)
}

pub fn coerce_bytes_of_struct_to_type_at_offset<StructType, DestinationType>(
    structure: &StructType,
    offset: usize,
) -> Result<DestinationType>
where
    DestinationType: Copy,
{
    if offset + std::mem::size_of::<DestinationType>() > std::mem::size_of::<StructType>() {
        return Err(anyhow!("Offset out of bounds for user struct"));
    }
    // SAFETY: We ensure that the offset is within bounds and that the size of DestinationType is valid.
    unsafe {
        let src_ptr = (structure as *const StructType as *const u8).add(offset);
        let mut value: DestinationType = zeroed::<DestinationType>();
        std::ptr::copy_nonoverlapping(
            src_ptr,
            &mut value as *mut DestinationType as *mut u8,
            size_of::<DestinationType>(),
        );
        Ok(value)
    }
}

pub fn as_mutable_bytes_of_struct<'a, StructType>(structure: &'a mut StructType) -> &'a mut [u8] {
    // SAFETY: We assume that the caller ensures that the structure is valid and properly aligned.
    unsafe {
        std::slice::from_raw_parts_mut(
            structure as *mut StructType as *mut u8,
            std::mem::size_of::<StructType>(),
        )
    }
}

pub fn as_bytes_of_struct<'a, StructType>(structure: &'a StructType) -> &'a [u8] {
    // SAFETY: We assume that the caller ensures that the structure is valid and properly aligned.
    unsafe {
        std::slice::from_raw_parts(
            structure as *const StructType as *const u8,
            std::mem::size_of::<StructType>(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    LongDouble([u8; 16]), // Assuming we can fit a long double in 16 bytes
    Byte64([u8; 8]),
    Byte128([u8; 16]),
}

/// Helper: copy `src` into the first `src.len()` bytes of a zero-filled [u8; 16].
fn pad_16(src: &[u8]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    for (i, byte) in src.iter().enumerate() {
        buf[i] = *byte;
    }
    buf
}

/// Helper macro: avoids writing `.to_le_bytes()` + `pad_16` 14 times.
macro_rules! widen {
    ($v:expr) => {{
        #[allow(clippy::useless_conversion)]
        pad_16(&($v).to_le_bytes())
    }};
}

impl RegisterValue {
    pub fn parse(mut input: &str, reg_info: &RegisterInfo) -> Result<Self> {
        // This function should parse a string input and return a RegisterValue.
        // The input can be a number, a hex string, or a floating point number.
        match reg_info.reg_format {
            RegisterFormat::UnsignedInt => {
                if input.starts_with("0x") || input.starts_with("0X") {
                    match reg_info.size {
                        1 => {
                            // Treat as unsigned 8-bit integer
                            return Ok(RegisterValue::U8(
                                u8::from_str_radix(&input[2..], 16)
                                    .context("Failed to parse hex string")?,
                            ));
                        }
                        2 => {
                            // Treat as unsigned 16-bit integer
                            return Ok(RegisterValue::U16(
                                u16::from_str_radix(&input[2..], 16)
                                    .context("Failed to parse hex string")?,
                            ));
                        }
                        4 => {
                            // Treat as unsigned 32-bit integer
                            return Ok(RegisterValue::U32(
                                u32::from_str_radix(&input[2..], 16)
                                    .context("Failed to parse hex string")?,
                            ));
                        }
                        8 => {
                            // Treat as unsigned 64-bit integer
                            return Ok(RegisterValue::U64(
                                u64::from_str_radix(&input[2..], 16)
                                    .context("Failed to parse hex string")?,
                            ));
                        }
                        _ => anyhow::bail!(
                            "Unsupported size for unsigned integer: {}",
                            reg_info.size
                        ),
                    }
                } else if input.starts_with("-0x") || input.starts_with("-0X") {
                    // Treat as signed integer
                    let unsigned_value = u64::from_str_radix(&input[3..], 16)
                        .context("Failed to parse hex string")?;
                    if unsigned_value > i64::MAX as u64 {
                        anyhow::bail!("Value out of range for signed integer");
                    }
                    let signed_value = -(unsigned_value as i64);
                    match reg_info.size {
                        1 => {
                            // Treat as signed 8-bit integer
                            return Ok(RegisterValue::I8(signed_value as i8));
                        }
                        2 => {
                            // Treat as signed 16-bit integer
                            return Ok(RegisterValue::I16(signed_value as i16));
                        }
                        4 => {
                            // Treat as signed 32-bit integer
                            return Ok(RegisterValue::I32(signed_value as i32));
                        }
                        8 => {
                            // Treat as signed 64-bit integer
                            return Ok(RegisterValue::I64(signed_value));
                        }
                        _ => {
                            anyhow::bail!("Unsupported size for signed integer: {}", reg_info.size)
                        }
                    }
                } else {
                    // Treat as decimal integer
                    if input.starts_with('-') {
                        // Signed integer
                        let signed_value: i64 = input
                            .parse()
                            .context("Failed to parse signed integer string")?;
                        match reg_info.size {
                            1 => return Ok(RegisterValue::I8(signed_value as i8)),
                            2 => return Ok(RegisterValue::I16(signed_value as i16)),
                            4 => return Ok(RegisterValue::I32(signed_value as i32)),
                            8 => return Ok(RegisterValue::I64(signed_value)),
                            _ => anyhow::bail!(
                                "Unsupported size for signed integer: {}",
                                reg_info.size
                            ),
                        }
                    } else {
                        // Unsigned integer
                        let unsigned_value: u64 = input
                            .parse()
                            .context("Failed to parse unsigned integer string")?;
                        match reg_info.size {
                            1 => return Ok(RegisterValue::U8(unsigned_value as u8)),
                            2 => return Ok(RegisterValue::U16(unsigned_value as u16)),
                            4 => return Ok(RegisterValue::U32(unsigned_value as u32)),
                            8 => return Ok(RegisterValue::U64(unsigned_value)),
                            _ => anyhow::bail!(
                                "Unsupported size for unsigned integer: {}",
                                reg_info.size
                            ),
                        }
                    }
                }
            }
            RegisterFormat::DoubleFloat => {
                // Floating point numbers
                match reg_info.size {
                    4 => {
                        // Treat as 32-bit float
                        return Ok(RegisterValue::F32(
                            input
                                .parse::<f32>()
                                .context("Failed to parse float string")?,
                        ));
                    }
                    8 => {
                        // Treat as 64-bit double
                        return Ok(RegisterValue::F64(
                            input
                                .parse::<f64>()
                                .context("Failed to parse double string")?,
                        ));
                    }
                    _ => anyhow::bail!(
                        "Unsupported size for floating point number: {}",
                        reg_info.size
                    ),
                }
            }
            RegisterFormat::LongDouble => {
                // Long double numbers
                let fp64_value = input
                    .parse::<f64>()
                    .context("Failed to parse long double string")?;
                let extended_value = Extended::from(fp64_value);
                return Ok(RegisterValue::LongDouble({
                    let mut bytes = [0u8; 16];
                    bytes[0..10].copy_from_slice(&extended_value.to_le_bytes());
                    bytes
                }));
            }
            RegisterFormat::Vector => {
                if !input.starts_with("0x") && !input.starts_with("0X") {
                    anyhow::bail!("Vector registers must be specified in hex format");
                }
                // Vector registers (byte arrays)
                input = &input[2..]; // Remove "0x" prefix
                match reg_info.size {
                    8 => {
                        // Treat as 64-bit vector
                        let mut bytes = [0u8; 8];
                        if input.len() != 16 {
                            anyhow::bail!("Invalid length for 64-bit vector: {}", input.len());
                        }
                        for (i, byte) in input.as_bytes().chunks(2).enumerate() {
                            bytes[i] = u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 16)
                                .context("Failed to parse hex string")?;
                        }
                        return Ok(RegisterValue::Byte64(bytes));
                    }
                    16 => {
                        // Treat as 128-bit vector
                        let mut bytes = [0u8; 16];
                        if input.len() != 32 {
                            anyhow::bail!("Invalid length for 128-bit vector: {}", input.len());
                        }
                        for (i, byte) in input.as_bytes().chunks(2).enumerate() {
                            bytes[i] = u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 16)
                                .context("Failed to parse hex string")?;
                        }
                        return Ok(RegisterValue::Byte128(bytes));
                    }
                    _ => anyhow::bail!("Unsupported size for vector register: {}", reg_info.size),
                }
            }
        }
    }

    pub fn get_payload_size_in_bytes(&self) -> usize {
        match self {
            RegisterValue::U8(_) | RegisterValue::I8(_) => 1,
            RegisterValue::U16(_) | RegisterValue::I16(_) => 2,
            RegisterValue::U32(_) | RegisterValue::I32(_) => 4,
            RegisterValue::U64(_) | RegisterValue::I64(_) => 8,
            RegisterValue::F32(_) => 4,
            RegisterValue::F64(_) => 8,
            RegisterValue::LongDouble(_) => 16,
            RegisterValue::Byte64(_) => 8,
            RegisterValue::Byte128(_) => 16,
        }
    }
    /// Turn any `RegisterValue` into a fixed 128-bit (16-byte) little-endian blob.
    pub fn widen_to_fixed_buffer(&self, info: &RegisterInfo) -> [u8; 16] {
        use RegisterFormat::*;
        // Note: All the to_le_bytes are because this is a little-endian architecture.
        match (self, info.reg_format, info.size) {
            // ────────────── floating-point widening ──────────────
            (RegisterValue::F32(v), DoubleFloat, ..) => widen!(*v as f64),
            (RegisterValue::F32(v), LongDouble, ..) => pad_16(&Extended::from(*v).to_le_bytes()),
            (RegisterValue::F64(v), LongDouble, ..) => pad_16(&Extended::from(*v).to_le_bytes()),

            // ────────────── integer widening ──────────────
            (RegisterValue::I8(v), UnsignedInt, 2) => widen!(*v as i16),
            (RegisterValue::I8(v), UnsignedInt, 4) => widen!(*v as i32),
            (RegisterValue::I8(v), UnsignedInt, 8) => widen!(*v as i64),
            (RegisterValue::I16(v), UnsignedInt, 4) => widen!(*v as i32),
            (RegisterValue::I16(v), UnsignedInt, 8) => widen!(*v as i64),
            (RegisterValue::I32(v), UnsignedInt, 8) => widen!(*v as i64),

            // ────────────── everything else ──────────────
            (RegisterValue::LongDouble(bytes), ..) => bytes.clone(),
            (RegisterValue::Byte64(bytes), ..) => pad_16(bytes),
            (RegisterValue::Byte128(bytes), ..) => pad_16(bytes),

            // Numeric values that *don’t* need special widening
            (RegisterValue::U8(v), ..) => widen!(v),
            (RegisterValue::U16(v), ..) => widen!(v),
            (RegisterValue::U32(v), ..) => widen!(v),
            (RegisterValue::U64(v), ..) => widen!(v),
            (RegisterValue::I8(v), ..) => widen!(v),
            (RegisterValue::I16(v), ..) => widen!(v),
            (RegisterValue::I32(v), ..) => widen!(v),
            (RegisterValue::I64(v), ..) => widen!(v),
            (RegisterValue::F32(v), ..) => widen!(v),
            (RegisterValue::F64(v), ..) => widen!(v),
        }
    }
}

impl Display for RegisterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterValue::U8(v) => write!(f, "{}", v),
            RegisterValue::U16(v) => write!(f, "{}", v),
            RegisterValue::U32(v) => write!(f, "{}", v),
            RegisterValue::U64(v) => write!(f, "0x{:x}", v),
            RegisterValue::I8(v) => write!(f, "{}", v),
            RegisterValue::I16(v) => write!(f, "{}", v),
            RegisterValue::I32(v) => write!(f, "{}", v),
            RegisterValue::I64(v) => write!(f, "{}", v),
            RegisterValue::F32(v) => write!(f, "{}", v),
            RegisterValue::F64(v) => write!(f, "{}", v),
            RegisterValue::LongDouble(bytes) => {
                let hex_string: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "0x{}", hex_string)
            }
            RegisterValue::Byte64(bytes) => {
                let hex_string: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "[{}]", hex_string)
            }
            RegisterValue::Byte128(bytes) => {
                let hex_string: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "[{}]", hex_string)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, zeroed};

    use super::*;

    // Test the gpr_offset macro for the x86_64 architecture.
    const _: () = assert!(gpr_offset!(r15) == 0);
    const _: () = assert!(gpr_offset!(r14) == gpr_offset!(r15) + 8);
    const _: () = assert!(gpr_offset!(r13) == gpr_offset!(r14) + 8);
    const _: () = assert!(gpr_offset!(gs) == size_of::<libc::user_regs_struct>() - 8);

    // Test the fpr_offset macro for the x86_64 architecture.
    const _: () = assert!(fpr_offset!(cwd) == offset_of!(libc::user, i387));
    const _: () = assert!(fpr_offset!(swd) == fpr_offset!(cwd) + fpr_size!(cwd));
    const _: () = assert!(fpr_offset!(xmm_space) == fpr_offset!(st_space) + fpr_size!(st_space));

    #[test]
    fn test_fpr() {
        let st0 = get_register_info(RegisterId::st(0));
        assert!(st0.is_some());
        let st0 = st0.unwrap();
        assert_eq!(st0.name, "st0");
        assert_eq!(st0.size, 16);
        assert_eq!(st0.offset, fpr_offset!(st_space));

        let st1 = get_register_info(RegisterId::st(1));
        assert!(st1.is_some());
        let st1 = st1.unwrap();
        assert_eq!(st1.name, "st1");
        assert_eq!(st1.size, 16); // Size of each ST register is 16 bytes. In x86_64, this is typically a long double, which is FP80.
        assert_eq!(st1.offset, fpr_offset!(st_space) + 16); // Offset for st1 is 16 bytes after st0
    }

    #[test]
    fn test_coerce_bytes_of_struct_to_type_at_offset() {
        let mut user = unsafe { zeroed::<libc::user>() };
        user.regs.r15 = 42; // Set r15 to a known value for testing
        assert_eq!(
            coerce_bytes_of_struct_to_type_at_offset::<libc::user, u64>(&user, gpr_offset!(r15))
                .unwrap(),
            42
        );
        user.regs.rbp = 84; // Set rbp to a known value for testing
        assert_eq!(
            coerce_bytes_of_struct_to_type_at_offset::<libc::user, libc::c_ulonglong>(
                &user,
                gpr_offset!(rbp)
            )
            .unwrap(),
            84
        );
        user.i387.cwd = 0x1234; // Set cwd to a known value for testing
        assert_eq!(
            coerce_bytes_of_struct_to_type_at_offset::<libc::user, u16>(&user, fpr_offset!(cwd))
                .unwrap(),
            0x1234
        );
        user.i387.st_space[1] = 0x5678;
        assert_eq!(
            coerce_bytes_of_struct_to_type_at_offset::<libc::user, u64>(
                &user,
                fpr_offset!(st_space) + 4
            )
            .unwrap(),
            0x5678
        );
        user.i387.st_space[4] = u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]);
        user.i387.st_space[5] = u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]);
        user.i387.st_space[6] = u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]);
        user.i387.st_space[7] = u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            coerce_bytes_of_struct_to_type_at_offset::<libc::user, [u8; 16]>(
                &user,
                get_register_info(RegisterId::st(1)).unwrap().offset
            )
            .unwrap(),
            [0xff; 16]
        );
    }

    // Test the dr_offset macro for the x86_64 architecture.
    const _: () = assert!(dr_offset!(0) == offset_of!(libc::user, u_debugreg));

    #[test]
    fn test_register_value_parsing() {
        {
            let register_info =
                get_register_info(RegisterId::r13).expect("Failed to get register info for r13");
            let value = RegisterValue::parse("0xdeadbeef", &register_info)
                .expect("Failed to parse register value");
            assert!(matches!(value, RegisterValue::U64(0xdeadbeef)));
        }
        {
            let register_info =
                get_register_info(RegisterId::r13).expect("Failed to get register info for r13");
            let value = RegisterValue::parse("-0xdeadbeef", &register_info)
                .expect("Failed to parse register value");
            assert!(matches!(value, RegisterValue::I64(-0xdeadbeef)));
        }
        {
            let register_info =
                get_register_info(RegisterId::r13).expect("Failed to get register info for r13");
            let value = RegisterValue::parse("-0xdeadbeef", &register_info)
                .expect("Failed to parse register value");
            assert!(matches!(value, RegisterValue::I64(-0xdeadbeef)));
        }
        {
            let register_info =
                get_register_info(RegisterId::r13).expect("Failed to get register info for r13");
            assert!(RegisterValue::parse("-9223372036854775809", &register_info).is_err());
        }
        {
            let register_info =
                get_register_info(RegisterId::r13b).expect("Failed to get register info for r13b");
            let value = RegisterValue::parse("255", &register_info)
                .expect("Failed to parse register value");
            assert!(matches!(value, RegisterValue::U8(255)));
        }
        {
            let register_info =
                get_register_info(RegisterId::st(0)).expect("Failed to get register info for st0");
            const CONSTANT: f64 = 0.5f64;
            let value = RegisterValue::parse(CONSTANT.to_string().as_str(), &register_info)
                .expect("Failed to parse register value");
            let _expected_bytes: [u8; 16] = {
                let mut bytes = [0u8; 16];
                bytes[0..10].copy_from_slice(&Extended::from(CONSTANT).to_le_bytes());
                bytes
            };
            assert!(matches!(value, RegisterValue::LongDouble(_expected_bytes)));
        }
        {
            let register_info =
                get_register_info(RegisterId::mm(0)).expect("Failed to get register info for mm0");
            let value = RegisterValue::parse("0xffffffffffffff00", &register_info)
                .expect("Failed to parse register value");
            let _expected_bytes: [u8; 8] = 0xffffff00u64.to_le_bytes();
            assert!(matches!(value, RegisterValue::Byte64(_expected_bytes)));
        }
        {
            let register_info = get_register_info(RegisterId::xmm(0))
                .expect("Failed to get register info for xmm0");
            let value = RegisterValue::parse(
                format!("0x{}", "ab".repeat(16).as_str()).as_str(),
                &register_info,
            )
            .expect("Failed to parse register value");
            let _expected_bytes: [u8; 16] = {
                let mut bytes = [0u8; 16];
                for (i, byte) in "ab".repeat(16).as_bytes().chunks(2).enumerate() {
                    bytes[i] = u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 16)
                        .expect("Failed to parse byte");
                }
                bytes
            };
            assert!(matches!(value, RegisterValue::Byte128(_expected_bytes)));
        }
    }
}
