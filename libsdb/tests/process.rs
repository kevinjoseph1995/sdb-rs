/////////////////////////////////////////
use std::path::PathBuf;
/////////////////////////////////////////
use anyhow::{Context, Result, anyhow};
use extended::Extended;
use nix::sys::{signal::Signal, wait::WaitStatus};
use procfs::process::MMPermissions;
use test_binary::build_test_binary;
/////////////////////////////////////////
use libsdb::{
    Pid,
    pipe_channel::{ChannelPort, create_pipe_channel},
    process::{Process, ProcessState, VirtAddress, get_process_state, process_with_pid_exists},
    register_info::{self, RegisterValue},
};
/////////////////////////////////////////

#[test]
fn test_process_launching() {
    let executable_path = PathBuf::from("ls");
    let args = Some("-l".to_string());
    let process_handle = Process::launch(&executable_path, args, true, None);
    assert!(process_handle.is_ok());
}
#[test]
fn test_process_launching_missing_executable() {
    let executable_path = PathBuf::from("executable_that_does_not_exist");
    let process_handle = Process::launch(&executable_path, None, true, None);
    assert!(process_handle.is_err(), "{}", process_handle.err().unwrap());
}

#[test]
fn test_process_exists() {
    let pid: Pid = {
        let executable_path = PathBuf::from("yes");
        let process_handle = Process::launch(&executable_path, None, true, None);
        let process_handle = process_handle.expect("Process failed to launch");
        assert!(process_handle.exists());
        process_handle.pid
        // The process should get terminated at the end of this scope
    };
    assert!(!process_with_pid_exists(pid));
}

#[test]
fn test_process_attach() {
    let target_process = Process::launch(
        &PathBuf::from("yes"),
        None,
        false, /*Note that we're not going to trace this process that's being launched */
        None,
    )
    .expect("Process failed to launch");
    let attached_process = Process::attach(target_process.pid).expect("Failed to attach");
    assert_eq!(attached_process.pid, target_process.pid);
    assert_eq!(
        get_process_state(attached_process.pid).unwrap(),
        ProcessState::TracingStopped
    );
}

#[test]
fn test_process_attach_failure() {
    let attached_process = Process::attach(Pid::from_raw(0));
    assert!(attached_process.is_err());
}

#[test]
fn test_process_resume() {
    let mut target_process =
        Process::launch(&PathBuf::from("yes"), None, true, None).expect("Process failed to launch");
    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::TracingStopped
    );
    target_process
        .resume_process()
        .expect("Failed to resume process");
    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::Running
    );
}
#[test]
fn test_process_resume_not_attached() {
    let target_process = Process::launch(&PathBuf::from("yes"), None, false, None)
        .expect("Process failed to launch");
    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::Running
    );

    let mut attached_handle = Process::attach(target_process.pid).expect("Failed to attach");
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(attached_handle.pid, target_process.pid);
    assert_eq!(
        get_process_state(attached_handle.pid).unwrap(),
        ProcessState::TracingStopped
    );
    attached_handle
        .resume_process()
        .expect("Failed to resume process");
    assert_eq!(
        get_process_state(attached_handle.pid).unwrap(),
        ProcessState::Running
    );
}

// Re-enable this test when artifact dependencies are made stable
#[test]
fn test_register_write() {
    let (read_port, write_port) = create_pipe_channel(true).expect("Failed to create pipe channel");
    let mut target_process = Process::launch(
        &PathBuf::from(
            build_test_binary("reg_write", &PathBuf::from_iter(["..", "tools"]))
                .expect("Failed to build test binary"),
        ),
        None,
        true,
        Some(write_port.into_internal_fd()),
    )
    .expect("Process failed to launch");
    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::TracingStopped
    );
    target_process
        .resume_process()
        .expect("1: Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("2: Failed to wait for process");

    target_process
        .write_register_value(
            register_info::RegisterId::rsi,
            RegisterValue::U64(0xdeadbeef),
        )
        .expect("Failed to write rsi register value");
    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let rsi_value = read_port.read().expect("Failed to read from pipe");
    let rsi_value_str = String::from_utf8(rsi_value).expect("Failed to convert to string");
    assert_eq!(
        rsi_value_str.trim(),
        "0xdeadbeef",
        "Expected rsi value to be 0xdeadbeef, got: {}",
        rsi_value_str
    );

    target_process
        .write_register_value(
            register_info::RegisterId::mm(0),
            RegisterValue::U64(0xba5eba11),
        )
        .expect("Failed to write mm0 register value");
    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let mm0_value = read_port.read().expect("Failed to read from pipe");
    let mm0_value_str = String::from_utf8(mm0_value).expect("Failed to convert to string");
    assert_eq!(
        mm0_value_str.trim(),
        "0xba5eba11",
        "Expected mm0 value to be 0xba5eba11, got: {}",
        mm0_value_str
    );

    target_process
        .write_register_value(register_info::RegisterId::xmm(0), RegisterValue::F64(42.24))
        .expect("Failed to write mm0 register value");
    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    let xmm0_value = read_port.read().expect("Failed to read from pipe");
    let xmm0_value_str = String::from_utf8(xmm0_value).expect("Failed to convert to string");
    assert_eq!(
        xmm0_value_str.trim(),
        "42.24",
        "Expected xmm0 value to be 42.24, got: {}",
        xmm0_value_str
    );

    target_process
        .write_register_value(
            register_info::RegisterId::st(0),
            RegisterValue::LongDouble({
                let mut long_double_value = [0u8; 16];
                for (i, byte) in Extended::from(3.14).to_le_bytes().iter().enumerate() {
                    long_double_value[i] = *byte;
                }
                long_double_value
            }),
        )
        .expect("Failed to write st0 register value");

    target_process
        .write_register_value(
            register_info::RegisterId::fsw,
            RegisterValue::U16(0b0011100000000000),
        )
        .expect("Failed to write st0 register value");
    target_process
        .write_register_value(
            register_info::RegisterId::ftw,
            RegisterValue::U16(0b0011111111111111),
        )
        .expect("Failed to write st0 register value");
    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    let st0_value = read_port.read().expect("Failed to read from pipe");
    let st0_value_str = String::from_utf8(st0_value).expect("Failed to convert to string");
    assert_eq!(
        st0_value_str.trim(),
        "3.14",
        "Expected st0 value to be 3.14, got: {}",
        st0_value_str
    );
}

// Re-enable this test when artifact dependencies are made stable
#[test]
fn test_register_read() {
    let (_read_port, write_port) =
        create_pipe_channel(true).expect("Failed to create pipe channel");
    let mut target_process = Process::launch(
        &PathBuf::from(
            build_test_binary("reg_read", &PathBuf::from_iter(["..", "tools"]))
                .expect("Failed to build test binary"),
        ),
        None,
        true,
        Some(write_port.into_internal_fd()),
    )
    .expect("Process failed to launch");
    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::TracingStopped
    );

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let value = target_process
        .get_registers()
        .get_register_value(register_info::RegisterId::r13)
        .expect("Failed to read r13 register value");
    assert!(matches!(value, RegisterValue::U64(0xcafecafe)));

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let value = target_process
        .get_registers()
        .get_register_value(register_info::RegisterId::r13b)
        .expect("Failed to read r13b register value");
    assert!(matches!(value, RegisterValue::U8(42)));

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let value = target_process
        .get_registers()
        .get_register_value(register_info::RegisterId::mm(0))
        .expect("Failed to read mm0 register value");
    let _expected_bytes: [u8; 8] = 0xba5eba11u64.to_le_bytes();
    assert!(matches!(value, RegisterValue::Byte64(_expected_bytes)));

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let value = target_process
        .get_registers()
        .get_register_value(register_info::RegisterId::xmm(0))
        .expect("Failed to read xmm0 register value");
    let expected_bytes: [u8; 8] = 64.125f64.to_le_bytes();
    let _expected_bytes_widened: [u8; 16] = {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&expected_bytes);
        bytes
    };
    assert!(matches!(
        value,
        RegisterValue::Byte128(_expected_bytes_widened)
    ));

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");

    let value = target_process
        .get_registers()
        .get_register_value(register_info::RegisterId::st(0))
        .expect("Failed to read st0 register value");
    let expected_bytes: [u8; 10] = Extended::from(64.125f64).to_le_bytes();
    let _expected_bytes_widened: [u8; 16] = {
        let mut bytes = [0u8; 16];
        bytes[0..10].copy_from_slice(&expected_bytes);
        bytes
    };
    assert!(matches!(
        value,
        RegisterValue::LongDouble(_expected_bytes_widened)
    ));
}

#[test]
fn test_create_breakpoint_site() {
    let mut target_process =
        Process::launch(&PathBuf::from("yes"), None, true, None).expect("Process failed to launch");
    {
        assert_eq!(
            target_process
                .create_breakpoint(VirtAddress::new(0x1000), false, false)
                .expect("Failed to create breakpoint site at 0x1000")
                .virtual_address(),
            VirtAddress::new(0x1000)
        );
    }
    assert_eq!(
        target_process
            .create_breakpoint(VirtAddress::new(0x2000), false, false)
            .expect("Failed to create breakpoint site at 0x2000")
            .id()
            + 1,
        target_process
            .create_breakpoint(VirtAddress::new(0x3000), false, false)
            .expect("Failed to create breakpoint site at 0x3000")
            .id()
    );
    assert!(
        target_process
            .create_breakpoint(VirtAddress::new(0x1000), false, false)
            .is_err(), // Should fail because breakpoint already exists at 0x1000
        "Expected to fail creating breakpoint site at 0x1000 again"
    );
}

/// Computes the section load bias for the given ELF file.
/// The section load bias is the difference between the address of the `.text` section and
/// the offset of the `.text` section in the file.
fn compute_section_load_bias(file: &elf::ElfBytes<elf::endian::AnyEndian>) -> Result<u64> {
    /* From Man 5 elf:
     sh_addr
           If this section appears in the memory image of a process,
           this member holds the address at which the section's first
           byte should reside.  Otherwise, the member contains zero.

    sh_offset
           This member's value holds the byte offset from the
           beginning of the file to the first byte in the section.
           One section type, SHT_NOBITS, occupies no space in the
           file, and its sh_offset member locates the conceptual
           placement in the file.
      */
    let text_section_header = file
        .section_header_by_name(".text")
        .expect("Failed to find .text section")
        .expect("Failed to find .text section");
    let load_bias: u64 = text_section_header.sh_addr - text_section_header.sh_offset;
    Ok(load_bias)
}

/// Computes the entry point offset from the start of the file.
/// This is the offset from the start of the file to the entry point address.
/// The entry point address is the address where the program starts executing.
/// The offset is computed by subtracting the section load bias from the entry point address.
fn get_entry_point_offset(file_path: &PathBuf) -> Result<usize> {
    let file = std::fs::read(file_path).expect("Could not read file.");
    let file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(file.as_slice())
        .expect("Failed to parse ELF file");
    let section_load_bias =
        compute_section_load_bias(&file).expect("Failed to compute section load bias");
    let entry_point_offset =
        file.ehdr
            .e_entry
            .checked_sub(section_load_bias)
            .ok_or_else(|| anyhow!("Failed to compute entry point address"))? as usize;

    Ok(entry_point_offset)
}

fn get_load_address(pid: Pid, offset: u64) -> Result<VirtAddress> {
    let process_entry =
        procfs::process::Process::new(pid.as_raw()).context("Failed to get process entry")?;
    let maps = process_entry.maps()?;
    let executable_map = maps
        .iter()
        .find(|m| m.perms.contains(MMPermissions::EXECUTE))
        .expect("Failed to find executable map");
    let file_offset = executable_map.offset;
    let (range_begin, _) = &executable_map.address;
    return Ok(VirtAddress::new(
        (range_begin + offset - file_offset) as usize,
    ));
}

#[test]
fn test_breakpoint_setting() {
    let test_binary_path = PathBuf::from(
        build_test_binary("hello_sdb", &PathBuf::from_iter(["..", "tools"]))
            .expect("Failed to build test binary"),
    );
    let offset =
        get_entry_point_offset(&test_binary_path).expect("Failed to get entry point offset");
    let mut target_process =
        Process::launch(&test_binary_path, None, true, None).expect("Process failed to launch");

    let load_address =
        get_load_address(target_process.pid, offset as u64).expect("Failed to get load address");
    let _ = target_process
        .create_breakpoint(load_address, true, false)
        .expect("Failed to create breakpoint site at load address");
    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::TracingStopped,
    );
    target_process
        .resume_process()
        .expect("Failed to resume process");
    let wait_status = target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    assert!(matches!(
        wait_status,
        WaitStatus::Stopped(_, Signal::SIGTRAP)
    ));
    // The process should have stopped at the breakpoint.
    let pc = target_process
        .get_pc()
        .expect("Failed to get program counter");
    assert_eq!(
        pc, load_address,
        "Process did not stop at the expected breakpoint address: {}",
        load_address
    );
}

#[test]
fn test_hardware_breakpoints() {
    let test_binary_path = PathBuf::from(
        build_test_binary("anti_debugger", &PathBuf::from_iter(["..", "tools"]))
            .expect("Failed to build test binary"),
    );
    let (read_port, write_port) = create_pipe_channel(true).expect("Failed to create pipe channel");
    let mut target_process = Process::launch(
        &test_binary_path,
        None,
        true,
        Some(write_port.into_internal_fd()),
    )
    .expect("Process failed to launch");

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    // Process should have raised a SIGTRAP signal and stopped.
    let stdout_from_child = read_port.read().expect("Failed to read from pipe channel");
    let address_string =
        String::from_utf8(stdout_from_child).expect("Failed to convert stdout to string");
    let address = usize::from_str_radix(address_string.trim(), 16).unwrap();

    // Create a software breakpoint at the address where the hardware breakpoint is set.
    let software_breakpoint_id = target_process
        .create_breakpoint(VirtAddress::new(address), true, false)
        .expect("Failed to create software breakpoint")
        .id();

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    // Process should have raised a SIGTRAP signal and stopped.
    // The inferior process should have recognized that it is being traced and modified it's execution flow.
    let stdout_from_child = read_port.read().expect("Failed to read from pipe channel");
    let output = String::from_utf8(stdout_from_child).expect("Failed to convert stdout to string");
    assert_eq!(
        output.trim(),
        "Checksum mismatch",
        "Expected output to be 'Checksum mismatch', got: {}",
        output
    );

    // Remove the software breakpoint
    target_process
        .remove_breakpoint_by_id(software_breakpoint_id)
        .expect("Failed to remove breakpoint");

    // This time use a hardware breakpoint.
    let _hardware_breakpoint_id = target_process
        .create_breakpoint(VirtAddress::new(address), true, true)
        .expect("Failed to create software breakpoint")
        .id();

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    // Process should have raised a SIGTRAP signal and stopped.

    let program_counter = target_process
        .get_pc()
        .expect("Failed to get program counter");
    assert_eq!(
        program_counter,
        VirtAddress::new(address),
        "Expected program counter to be at the breakpoint address: 0x{:x}, got: {}",
        address,
        program_counter
    );

    target_process
        .resume_process()
        .expect("Failed to resume process");
    target_process
        .wait_on_signal(None)
        .expect("Failed to wait for process");
    // Process should have raised a SIGTRAP signal and stopped.
    let stdout_from_child = read_port.read().expect("Failed to read from pipe channel");
    let output = String::from_utf8(stdout_from_child).expect("Failed to convert stdout to string");
    assert_eq!(
        output.trim(),
        "Unmodified",
        "Expected output to be 'Unmodified', got: {}",
        output  
    );
}

#[test]
fn test_memory_operations() {
    let test_binary_path = PathBuf::from(
        build_test_binary("memory_test", &PathBuf::from_iter(["..", "tools"]))
            .expect("Failed to build test binary"),
    );
    let (read_port, write_port) = create_pipe_channel(true).expect("Failed to create pipe channel");
    let mut target_process = Process::launch(
        &test_binary_path,
        None,
        true,
        Some(write_port.into_internal_fd()),
    )
    .expect("Process failed to launch");

    assert!(
        get_process_state(target_process.pid).expect("Failed to get process state")
            == ProcessState::TracingStopped,
    );

    {
        target_process
            .resume_process()
            .expect("Failed to resume process");
        target_process
            .wait_on_signal(None)
            .expect("Failed to wait for process");
        // Process should have raised a SIGTRAP signal and stopped.
        // Read the value of a local stack variable whose value we know is 0xdeadbeef.
        let stdout_from_child = read_port.read().expect("Failed to read from pipe channel");
        let address_string =
            String::from_utf8(stdout_from_child).expect("Failed to convert stdout to string");
        // The address string should be in the format "0x<address>"
        let address_to_read_from = u64::from_str_radix(&address_string[2..], 16)
            .expect("Failed to parse address from string");

        let value_read_bytes = target_process
            .read_memory(VirtAddress::new(address_to_read_from as usize), 8)
            .expect("Failed to read memory");

        let value_read_u64 = u64::from_le_bytes(value_read_bytes[0..8].try_into().unwrap());
        assert_eq!(
            value_read_u64, 0xdeadbeef,
            "Expected to read 0xdeadbeef from memory, got: 0x{:x}",
            value_read_u64
        );
    }
    {
        target_process
            .resume_process()
            .expect("Failed to resume process");
        target_process
            .wait_on_signal(None)
            .expect("Failed to wait for process");
        // Process should have raised a SIGTRAP signal and stopped.
        // Get the address of a local array variable.
        let stdout_from_child = read_port.read().expect("Failed to read from pipe channel");
        let address_string =
            String::from_utf8(stdout_from_child).expect("Failed to convert stdout to string");
        // The address string should be in the format "0x<address>"
        let array_address = u64::from_str_radix(&address_string[2..], 16)
            .expect("Failed to parse address from string");
        const CONST_STRING: &str = "Hello, sdb!";
        let values_to_write: [u8; 12] = {
            let mut array = [0; 12];
            for (i, char) in CONST_STRING.chars().enumerate() {
                array[i] = char as u8;
            }
            array[11] = 0; // Null-terminate the string
            array
        };
        target_process
            .write_memory(VirtAddress::new(array_address as usize), &values_to_write)
            .expect("Failed to write memory");
        target_process
            .resume_process()
            .expect("Failed to resume process");
        target_process
            .wait_on_signal(None)
            .expect("Failed to wait for process");
        let stdout_from_child = read_port.read().expect("Failed to read from pipe channel");
        // Compare with the bytes we wrote to the memory.
        values_to_write
            .iter()
            .zip(stdout_from_child.iter())
            .for_each(|(expected_byte, read_byte)| {
                assert_eq!(
                    expected_byte, read_byte,
                    "Expected byte {} to be {}, got: {}",
                    expected_byte, expected_byte, read_byte
                );
            });
    }
}
