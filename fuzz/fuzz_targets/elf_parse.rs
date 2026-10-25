#![no_main]

use libfuzzer_sys::fuzz_target;
use libsdb::elf::Elf;
use std::path::PathBuf;

// Elf::new mmaps a path, so each input goes through a file. /dev/shm keeps
// it in memory; the pid keeps parallel fuzz jobs apart.
fn scratch_path() -> PathBuf {
    PathBuf::from(format!("/dev/shm/sdb_fuzz_elf_{}", std::process::id()))
}

fuzz_target!(|data: &[u8]| {
    let path = scratch_path();
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let _ = Elf::new(&path);
});
