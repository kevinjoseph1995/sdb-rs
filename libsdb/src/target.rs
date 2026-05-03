use std::path::{Path, PathBuf};

use crate::{address::VirtAddress, elf::Elf, process::Process};
use anyhow::{Context, Result};
use libc::AT_ENTRY;

pub struct Target {
    pub process: Process,
    pub elf: Elf,
}

impl Target {
    pub fn launch(
        executable_path: &Path,
        args: Option<String>,
        debug_process_being_launched: bool,
        stdout_replacement: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self> {
        let process = Process::launch(
            executable_path,
            args,
            debug_process_being_launched,
            stdout_replacement,
        )?;
        let elf = Self::create_loaded_elf(&process, executable_path)?;
        Ok(Target { process, elf })
    }

    pub fn attach(pid: crate::Pid) -> Result<Self> {
        // https://docs.kernel.org/filesystems/proc.html
        // exe: Link to the executable of this process
        let executable_path = PathBuf::from_iter(["/proc", &pid.to_string(), "exe"]);
        let process = Process::attach(pid)?;
        let elf = Self::create_loaded_elf(&process, &executable_path)?;
        Ok(Target { process, elf })
    }

    fn create_loaded_elf(process: &Process, path: &Path) -> Result<Elf> {
        /*
        1. process.get_auxv() — reads the kernel's auxiliary vector for the process (from /proc/{pid}/auxv). This is a key-value table the kernel fills in at process startup with facts like the actual entry
        point address.
        2. Elf::new(path) — parses the ELF file from disk. At this point it only knows the static (file-relative) addresses — it doesn't know where the OS actually loaded it.
        3. auxv.get(&AT_ENTRY) — retrieves AT_ENTRY, which is the runtime virtual address of the program's entry point after the loader placed it in memory.
        4. Computing the load bias:
        load_bias = AT_ENTRY (runtime) − e_entry (from ELF header)
          - e_entry is the entry point address recorded in the ELF file — for a PIE binary this is a small offset from 0, not an absolute address.
          - AT_ENTRY is where that entry point actually landed in the process's address space.
          - The difference is the load bias — how far ASLR shifted the binary from where it thought it would live.
        5. elf.notify_loaded(load_bias) — stores the load bias in the Elf struct so it can later translate any symbol/section address from the file into the correct runtime virtual address (by adding the bias).
               */
        let auxv = process.get_auxv()?;
        let mut elf = Elf::new(path)?;
        let at_entry_value = auxv
            .get(&(AT_ENTRY as i32))
            .context("Failed to get entry address")?;
        elf.notify_loaded(VirtAddress::new(
            (at_entry_value - elf.header.e_entry)
                .try_into()
                .context("create_loaded_elf offset calculation underflow")?,
        ));
        return Ok(elf);
    }
}
