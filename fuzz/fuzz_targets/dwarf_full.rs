#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

// Same file-backed approach as elf_parse; this target goes on to walk the DWARF.
fn scratch_path() -> PathBuf {
    PathBuf::from(format!("/dev/shm/sdb_fuzz_dwarf_{}", std::process::id()))
}

fuzz_target!(|data: &[u8]| {
    let path = scratch_path();
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let _ = libsdb::dwarf::fuzz_api::walk_dwarf(&path);
});
