//! Source language of a compile unit, from its `DW_AT_language`.
//!
//! Language-specific niceties (e.g. demangling) match on this before applying
//! themselves, so they only touch code written in the language they understand.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    C,
    Cpp,
    Rust,
    /// Any other language, kept as its raw `DW_LANG_*` code.
    Other(u64),
}

impl SourceLanguage {
    /// Maps a `DW_LANG_*` code to a language. All versions of C (C89..C11)
    /// and C++ (C++03..C++14) map to one variant each.
    pub fn from_dw_lang(code: u64) -> Self {
        match code {
            0x01 | 0x02 | 0x0c | 0x1d => SourceLanguage::C,
            0x04 | 0x19 | 0x1a | 0x21 => SourceLanguage::Cpp,
            0x1c => SourceLanguage::Rust,
            other => SourceLanguage::Other(other),
        }
    }
}
