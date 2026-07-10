use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::address::FileAddress;
use crate::process::StopReason;
use crate::stack::Stack;
use crate::{address::VirtAddress, dwarf::Dwarf, elf::Elf, process::Process};
use anyhow::{Context, Result, anyhow};
use libc::AT_ENTRY;

pub struct TargetState {
    pub elf: Rc<Elf>,
    /// DWARF debug info, or `None` for a binary without a `.debug_info` section.
    pub dwarf: Option<Dwarf>,
    pub stack: Stack,
}

pub struct Target {
    pub process: Process,
    pub state: Rc<TargetState>,
}

impl Target {
    pub fn launch(
        executable_path: &Path,
        args: Option<String>,
        debug_process_being_launched: bool,
        stdout_replacement: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self> {
        let mut process = Process::launch(
            executable_path,
            args,
            debug_process_being_launched,
            stdout_replacement,
        )?;
        let (elf, dwarf) = Self::load(&process, executable_path)?;
        let state = Rc::new(TargetState {
            elf,
            dwarf,
            stack: Stack::new(),
        });
        process.target_state = Rc::downgrade(&state);
        Ok(Target { process, state })
    }

    pub fn attach(pid: crate::Pid) -> Result<Self> {
        // https://docs.kernel.org/filesystems/proc.html
        // exe: Link to the executable of this process
        let executable_path = PathBuf::from_iter(["/proc", &pid.to_string(), "exe"]);
        let mut process = Process::attach(pid)?;
        let (elf, dwarf) = Self::load(&process, &executable_path)?;
        let state = Rc::new(TargetState {
            elf,
            dwarf,
            stack: Stack::new(),
        });
        process.target_state = Rc::downgrade(&state);
        Ok(Target { process, state })
    }

    /// Loads the executable's ELF (with load bias applied) and its DWARF info, if any.
    fn load(process: &Process, path: &Path) -> Result<(Rc<Elf>, Option<Dwarf>)> {
        let elf = Rc::new(Self::create_loaded_elf(process, path)?);
        let dwarf = Dwarf::new(Rc::clone(&elf))?;
        Ok((elf, dwarf))
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

impl TargetState {
    pub fn get_pc_file_address(&self, process: &Process) -> Result<FileAddress<'_>> {
        let virt_address = process.get_pc()?;
        virt_address
            .to_file_address(&self.elf)
            .ok_or(anyhow!("Failed to convert virt_address to file_address"))
    }

    pub fn notify_stop(&self, process: &Process, _reason: &StopReason) -> Result<()> {
        self.stack.reset_inline_height(self, process)
    }
}
