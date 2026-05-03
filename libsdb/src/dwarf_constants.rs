// Ported to Rust from the original C header by TartanLlama:
// https://github.com/TartanLlama/sdb/blob/chapter-12/include/libsdb/detail/dwarf.h
//
// Original work Copyright (c) TartanLlama
// Licensed under the MIT License: https://opensource.org/licenses/MIT
//
// Conversion to Rust assisted by Claude (Anthropic).
// DWARF constants sourced from the DWARF standard and LSB specification.

#![allow(non_camel_case_types, clippy::upper_case_acronyms)]

// ---- DW_TAG ----------------------------------------------------------------

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwTag {
    ArrayType = 0x01,
    ClassType = 0x02,
    EntryPoint = 0x03,
    EnumerationType = 0x04,
    FormalParameter = 0x05,
    ImportedDeclaration = 0x08,
    Label = 0x0a,
    LexicalBlock = 0x0b,
    Member = 0x0d,
    PointerType = 0x0f,
    ReferenceType = 0x10,
    CompileUnit = 0x11,
    StringType = 0x12,
    StructureType = 0x13,
    SubroutineType = 0x15,
    Typedef = 0x16,
    UnionType = 0x17,
    UnspecifiedParameters = 0x18,
    Variant = 0x19,
    CommonBlock = 0x1a,
    CommonInclusion = 0x1b,
    Inheritance = 0x1c,
    InlinedSubroutine = 0x1d,
    Module = 0x1e,
    PtrToMemberType = 0x1f,
    SetType = 0x20,
    SubrangeType = 0x21,
    WithStmt = 0x22,
    AccessDeclaration = 0x23,
    BaseType = 0x24,
    CatchBlock = 0x25,
    ConstType = 0x26,
    Constant = 0x27,
    Enumerator = 0x28,
    FileType = 0x29,
    Friend = 0x2a,
    Namelist = 0x2b,
    NamelistItem = 0x2c,
    PackedType = 0x2d,
    Subprogram = 0x2e,
    TemplateTypeParameter = 0x2f,
    TemplateValueParameter = 0x30,
    ThrownType = 0x31,
    TryBlock = 0x32,
    VariantPart = 0x33,
    Variable = 0x34,
    VolatileType = 0x35,
    DwarfProcedure = 0x36,
    RestrictType = 0x37,
    InterfaceType = 0x38,
    Namespace = 0x39,
    ImportedModule = 0x3a,
    UnspecifiedType = 0x3b,
    PartialUnit = 0x3c,
    ImportedUnit = 0x3d,
    Condition = 0x3f,
    SharedType = 0x40,
    TypeUnit = 0x41,
    RvalueReferenceType = 0x42,
    TemplateAlias = 0x43,
    LoUser = 0x4080,
    HiUser = 0xffff,
}

// ---- DW_CHILDREN -----------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwChildren {
    No = 0x00,
    Yes = 0x01,
}

// ---- DW_AT -----------------------------------------------------------------

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwAt {
    Sibling = 0x01,
    Location = 0x02,
    Name = 0x03,
    Ordering = 0x09,
    ByteSize = 0x0b,
    BitOffset = 0x0c,
    BitSize = 0x0d,
    StmtList = 0x10,
    LowPc = 0x11,
    HighPc = 0x12,
    Language = 0x13,
    Discr = 0x15,
    DiscrValue = 0x16,
    Visibility = 0x17,
    Import = 0x18,
    StringLength = 0x19,
    CommonReference = 0x1a,
    CompDir = 0x1b,
    ConstValue = 0x1c,
    ContainingType = 0x1d,
    DefaultValue = 0x1e,
    Inline = 0x20,
    IsOptional = 0x21,
    LowerBound = 0x22,
    Producer = 0x25,
    Prototyped = 0x27,
    ReturnAddr = 0x2a,
    StartScope = 0x2c,
    BitStride = 0x2e,
    UpperBound = 0x2f,
    AbstractOrigin = 0x31,
    Accessibility = 0x32,
    AddressClass = 0x33,
    Artificial = 0x34,
    BaseTypes = 0x35,
    CallingConvention = 0x36,
    Count = 0x37,
    DataMemberLocation = 0x38,
    DeclColumn = 0x39,
    DeclFile = 0x3a,
    DeclLine = 0x3b,
    Declaration = 0x3c,
    DiscrList = 0x3d,
    Encoding = 0x3e,
    External = 0x3f,
    FrameBase = 0x40,
    Friend = 0x41,
    IdentifierCase = 0x42,
    MacroInfo = 0x43,
    NamelistItem = 0x44,
    Priority = 0x45,
    Segment = 0x46,
    Specification = 0x47,
    StaticLink = 0x48,
    Type = 0x49,
    UseLocation = 0x4a,
    VariableParameter = 0x4b,
    Virtuality = 0x4c,
    VtableElemLocation = 0x4d,
    Allocated = 0x4e,
    Associated = 0x4f,
    DataLocation = 0x50,
    ByteStride = 0x51,
    EntryPc = 0x52,
    UseUtf8 = 0x53,
    Extension = 0x54,
    Ranges = 0x55,
    Trampoline = 0x56,
    CallColumn = 0x57,
    CallFile = 0x58,
    CallLine = 0x59,
    Description = 0x5a,
    BinaryScale = 0x5b,
    DecimalScale = 0x5c,
    Small = 0x5d,
    DecimalSign = 0x5e,
    DigitCount = 0x5f,
    PictureString = 0x60,
    Mutable = 0x61,
    ThreadsScaled = 0x62,
    Explicit = 0x63,
    ObjectPointer = 0x64,
    Endianity = 0x65,
    Elemental = 0x66,
    Pure = 0x67,
    Recursive = 0x68,
    Signature = 0x69,
    MainSubprogram = 0x6a,
    DataBitOffset = 0x6b,
    ConstExpr = 0x6c,
    EnumClass = 0x6d,
    LinkageName = 0x6e,
    /// From DWARF5, but GCC still outputs in DWARF4 mode
    Defaulted = 0x8b,
    LoUser = 0x2000,
    HiUser = 0x3fff,
}

// ---- DW_DEFAULTED ----------------------------------------------------------
// From DWARF5, but GCC still outputs in DWARF4 mode

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwDefaulted {
    No = 0x00,
    InClass = 0x01,
    OutOfClass = 0x02,
}

// ---- DW_FORM ---------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwForm {
    Addr = 0x01,
    Block2 = 0x03,
    Block4 = 0x04,
    Data2 = 0x05,
    Data4 = 0x06,
    Data8 = 0x07,
    String = 0x08,
    Block = 0x09,
    Block1 = 0x0a,
    Data1 = 0x0b,
    Flag = 0x0c,
    Sdata = 0x0d,
    Strp = 0x0e,
    Udata = 0x0f,
    RefAddr = 0x10,
    Ref1 = 0x11,
    Ref2 = 0x12,
    Ref4 = 0x13,
    Ref8 = 0x14,
    RefUdata = 0x15,
    Indirect = 0x16,
    SecOffset = 0x17,
    Exprloc = 0x18,
    FlagPresent = 0x19,
    RefSig8 = 0x20,
}

// ---- DW_OP -----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwOp {
    Addr = 0x03,
    Deref = 0x06,
    Const1u = 0x08,
    Const1s = 0x09,
    Const2u = 0x0a,
    Const2s = 0x0b,
    Const4u = 0x0c,
    Const4s = 0x0d,
    Const8u = 0x0e,
    Const8s = 0x0f,
    Constu = 0x10,
    Consts = 0x11,
    Dup = 0x12,
    Drop = 0x13,
    Over = 0x14,
    Pick = 0x15,
    Swap = 0x16,
    Rot = 0x17,
    Xderef = 0x18,
    Abs = 0x19,
    And = 0x1a,
    Div = 0x1b,
    Minus = 0x1c,
    Mod = 0x1d,
    Mul = 0x1e,
    Neg = 0x1f,
    Not = 0x20,
    Or = 0x21,
    Plus = 0x22,
    PlusUconst = 0x23,
    Shl = 0x24,
    Shr = 0x25,
    Shra = 0x26,
    Xor = 0x27,
    Bra = 0x28,
    Eq = 0x29,
    Ge = 0x2a,
    Gt = 0x2b,
    Le = 0x2c,
    Lt = 0x2d,
    Ne = 0x2e,
    Skip = 0x2f,
    Lit0 = 0x30,
    Lit1 = 0x31,
    Lit2 = 0x32,
    Lit3 = 0x33,
    Lit4 = 0x34,
    Lit5 = 0x35,
    Lit6 = 0x36,
    Lit7 = 0x37,
    Lit8 = 0x38,
    Lit9 = 0x39,
    Lit10 = 0x3a,
    Lit11 = 0x3b,
    Lit12 = 0x3c,
    Lit13 = 0x3d,
    Lit14 = 0x3e,
    Lit15 = 0x3f,
    Lit16 = 0x40,
    Lit17 = 0x41,
    Lit18 = 0x42,
    Lit19 = 0x43,
    Lit20 = 0x44,
    Lit21 = 0x45,
    Lit22 = 0x46,
    Lit23 = 0x47,
    Lit24 = 0x48,
    Lit25 = 0x49,
    Lit26 = 0x4a,
    Lit27 = 0x4b,
    Lit28 = 0x4c,
    Lit29 = 0x4d,
    Lit30 = 0x4e,
    Lit31 = 0x4f,
    Reg0 = 0x50,
    Reg1 = 0x51,
    Reg2 = 0x52,
    Reg3 = 0x53,
    Reg4 = 0x54,
    Reg5 = 0x55,
    Reg6 = 0x56,
    Reg7 = 0x57,
    Reg8 = 0x58,
    Reg9 = 0x59,
    Reg10 = 0x5a,
    Reg11 = 0x5b,
    Reg12 = 0x5c,
    Reg13 = 0x5d,
    Reg14 = 0x5e,
    Reg15 = 0x5f,
    Reg16 = 0x60,
    Reg17 = 0x61,
    Reg18 = 0x62,
    Reg19 = 0x63,
    Reg20 = 0x64,
    Reg21 = 0x65,
    Reg22 = 0x66,
    Reg23 = 0x67,
    Reg24 = 0x68,
    Reg25 = 0x69,
    Reg26 = 0x6a,
    Reg27 = 0x6b,
    Reg28 = 0x6c,
    Reg29 = 0x6d,
    Reg30 = 0x6e,
    Reg31 = 0x6f,
    Breg0 = 0x70,
    Breg1 = 0x71,
    Breg2 = 0x72,
    Breg3 = 0x73,
    Breg4 = 0x74,
    Breg5 = 0x75,
    Breg6 = 0x76,
    Breg7 = 0x77,
    Breg8 = 0x78,
    Breg9 = 0x79,
    Breg10 = 0x7a,
    Breg11 = 0x7b,
    Breg12 = 0x7c,
    Breg13 = 0x7d,
    Breg14 = 0x7e,
    Breg15 = 0x7f,
    Breg16 = 0x80,
    Breg17 = 0x81,
    Breg18 = 0x82,
    Breg19 = 0x83,
    Breg20 = 0x84,
    Breg21 = 0x85,
    Breg22 = 0x86,
    Breg23 = 0x87,
    Breg24 = 0x88,
    Breg25 = 0x89,
    Breg26 = 0x8a,
    Breg27 = 0x8b,
    Breg28 = 0x8c,
    Breg29 = 0x8d,
    Breg30 = 0x8e,
    Breg31 = 0x8f,
    Regx = 0x90,
    Fbreg = 0x91,
    Bregx = 0x92,
    Piece = 0x93,
    DerefSize = 0x94,
    XderefSize = 0x95,
    Nop = 0x96,
    PushObjectAddress = 0x97,
    Call2 = 0x98,
    Call4 = 0x99,
    CallRef = 0x9a,
    FormTlsAddress = 0x9b,
    CallFrameCfa = 0x9c,
    BitPiece = 0x9d,
    ImplicitValue = 0x9e,
    StackValue = 0x9f,
    LoUser = 0xe0,
    HiUser = 0xff,
}

// ---- DW_ATE ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwAte {
    Address = 0x01,
    Boolean = 0x02,
    ComplexFloat = 0x03,
    Float = 0x04,
    Signed = 0x05,
    SignedChar = 0x06,
    Unsigned = 0x07,
    UnsignedChar = 0x08,
    ImaginaryFloat = 0x09,
    PackedDecimal = 0x0a,
    NumericString = 0x0b,
    Edited = 0x0c,
    SignedFixed = 0x0d,
    UnsignedFixed = 0x0e,
    DecimalFloat = 0x0f,
    Utf = 0x10,
    LoUser = 0x80,
    HiUser = 0xff,
}

// ---- DW_DS -----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwDs {
    Unsigned = 0x01,
    LeadingOverpunch = 0x02,
    TrailingOverpunch = 0x03,
    LeadingSeparate = 0x04,
    TrailingSeparate = 0x05,
}

// ---- DW_END ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwEnd {
    Default = 0x00,
    Big = 0x01,
    Little = 0x02,
    LoUser = 0x40,
    HiUser = 0xff,
}

// ---- DW_ACCESS -------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwAccess {
    Public = 0x01,
    Protected = 0x02,
    Private = 0x03,
}

// ---- DW_VIS ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwVis {
    Local = 0x01,
    Exported = 0x02,
    Qualified = 0x03,
}

// ---- DW_VIRTUALITY ---------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwVirtuality {
    None = 0x00,
    Virtual = 0x01,
    PureVirtual = 0x02,
}

// ---- DW_LANG ---------------------------------------------------------------

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwLang {
    C89 = 0x0001,
    C = 0x0002,
    Ada83 = 0x0003,
    CPlusPlus = 0x0004,
    Cobol74 = 0x0005,
    Cobol85 = 0x0006,
    Fortran77 = 0x0007,
    Fortran90 = 0x0008,
    Pascal83 = 0x0009,
    Modula2 = 0x000a,
    Java = 0x000b,
    C99 = 0x000c,
    Ada95 = 0x000d,
    Fortran95 = 0x000e,
    Pli = 0x000f,
    ObjC = 0x0010,
    ObjCPlusPlus = 0x0011,
    Upc = 0x0012,
    D = 0x0013,
    Python = 0x0014,
    LoUser = 0x8000,
    HiUser = 0xffff,
}

// ---- DW_ADDR ---------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwAddr {
    None = 0x00,
}

// ---- DW_ID -----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwId {
    CaseSensitive = 0x00,
    UpCase = 0x01,
    DownCase = 0x02,
    CaseInsensitive = 0x03,
}

// ---- DW_CC -----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwCc {
    Normal = 0x01,
    Program = 0x02,
    Nocall = 0x03,
    LoUser = 0x40,
    HiUser = 0xff,
}

// ---- DW_INL ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwInl {
    NotInlined = 0x00,
    Inlined = 0x01,
    DeclaredNotInlined = 0x02,
    DeclaredInlined = 0x03,
}

// ---- DW_ORD ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwOrd {
    RowMajor = 0x00,
    ColMajor = 0x01,
}

// ---- DW_DSC ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwDsc {
    Label = 0x00,
    Range = 0x01,
}

// ---- DW_LNS ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwLns {
    Copy = 0x01,
    AdvancePc = 0x02,
    AdvanceLine = 0x03,
    SetFile = 0x04,
    SetColumn = 0x05,
    NegateStmt = 0x06,
    SetBasicBlock = 0x07,
    ConstAddPc = 0x08,
    FixedAdvancePc = 0x09,
    SetPrologueEnd = 0x0a,
    SetEpilogueBegin = 0x0b,
    SetIsa = 0x0c,
}

// ---- DW_LNE ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwLne {
    EndSequence = 0x01,
    SetAddress = 0x02,
    DefineFile = 0x03,
    SetDiscriminator = 0x04,
    LoUser = 0x80,
    HiUser = 0xff,
}

// ---- DW_MACINFO ------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwMacinfo {
    Define = 0x01,
    Undef = 0x02,
    StartFile = 0x03,
    EndFile = 0x04,
    VendorExt = 0xff,
}

// ---- DW_CFA ----------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwCfa {
    AdvanceLoc = 0x40,
    Offset = 0x80,
    Restore = 0xc0,
    Nop = 0x00,
    SetLoc = 0x01,
    AdvanceLoc1 = 0x02,
    AdvanceLoc2 = 0x03,
    AdvanceLoc4 = 0x04,
    OffsetExtended = 0x05,
    RestoreExtended = 0x06,
    Undefined = 0x07,
    SameValue = 0x08,
    Register = 0x09,
    RememberState = 0x0a,
    RestoreState = 0x0b,
    DefCfa = 0x0c,
    DefCfaRegister = 0x0d,
    DefCfaOffset = 0x0e,
    DefCfaExpression = 0x0f,
    Expression = 0x10,
    OffsetExtendedSf = 0x11,
    DefCfaSf = 0x12,
    DefCfaOffsetSf = 0x13,
    ValOffset = 0x14,
    ValOffsetSf = 0x15,
    ValExpression = 0x16,
    LoUser = 0x1c,
    HiUser = 0x3f,
}

// ---- DW_EH_PE --------------------------------------------------------------
// From LSB

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwEhPe {
    Absptr = 0x00,
    Uleb128 = 0x01,
    Udata2 = 0x02,
    Udata4 = 0x03,
    Udata8 = 0x04,
    Sleb128 = 0x09,
    Sdata2 = 0x0a,
    Sdata4 = 0x0b,
    Sdata8 = 0x0c,
    Pcrel = 0x10,
    Textrel = 0x20,
    Datarel = 0x30,
    Funcrel = 0x40,
    Aligned = 0x50,
    /// GCC extension
    Indirect = 0x80,
}
