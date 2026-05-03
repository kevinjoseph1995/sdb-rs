use libsdb::elf::Elf;
use std::path::PathBuf;
use test_binary::build_test_binary;

#[test]
fn test_basic_elf_parsing() {
    let test_executable = PathBuf::from(
        build_test_binary("hello_sdb", &PathBuf::from_iter(["..", "tools"]))
            .expect("Failed to build test binary"),
    );

    let elf = Elf::new(&test_executable).expect("Failed to parse ELF");

    let file_address = libsdb::address::FileAddress {
        elf_handle: &elf,
        address: elf.header.e_entry as usize,
    };

    let symbol = elf
        .get_symbol_at_address(file_address)
        .expect("Failed to get entrypoint symbol");

    let name = elf
        .get_string(symbol.st_name as usize)
        .expect("Failed to get symbol name from string table");
    assert!(
        "_start" == name.to_str().expect("Failed to conver to a &str"),
        "Expect the entrypoint symbol to be \"_start\""
    );
}
