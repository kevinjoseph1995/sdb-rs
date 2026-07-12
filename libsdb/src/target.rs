use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::address::FileAddress;
use crate::dwarf::LineTableEntry;
use crate::process::{StopReason, TrapType};
use crate::stack::Stack;
use crate::{address::VirtAddress, dwarf::Dwarf, elf::Elf, process::Process};
use anyhow::{Context, Result, anyhow};
use libc::AT_ENTRY;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

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

/// Borrow-free identity of the line-table entry covering a PC, used to detect
/// when single-stepping has crossed onto a different source line.
#[derive(Clone, Copy)]
struct LineSnapshot {
    /// (address, file_index, line, column, discriminator) — the fields that
    /// distinguish one line-table row from another.
    line: (usize, u64, u64, u64, u64),
    /// Whether this row is an `end_sequence` marker (no real source line).
    end_sequence: bool,
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

    /// Step in:
    /// The basic idea behind the step in operation is to step through single machine instructions until
    /// the program counter lands on an instruction that belongs to a different line of source code from the
    /// one at which it began. When the program counter arrives at a new source line, it might have entered a
    /// new function. In that case, we also skip over the prologue of that function, which sets up the stack
    pub fn step_in(&mut self) -> Result<StopReason> {
        let stack = &self.state.stack;
        if stack.get_inline_height() > 0 {
            stack.simulate_inlined_step_in();
            return Ok(StopReason {
                wait_status: WaitStatus::Stopped(self.process.pid, Signal::SIGTRAP),
                trap_type: Some(crate::process::TrapType::SingleStep),
                syscall_info: None,
            });
        }
        // Single-step until we reach a different source line. `origin` is the
        // line covering the starting PC; we keep stepping while the PC stays on
        // that line or lands on an `end_sequence` row (which carries no real
        // line), and stop once it has no covering line at all.
        let origin = self.line_snapshot_at_pc()?;
        loop {
            let reason = self.process.step_instruction()?;
            if reason.wait_status != WaitStatus::Stopped(self.process.pid, Signal::SIGTRAP)
                || reason.trap_type != Some(TrapType::SingleStep)
            {
                return Ok(reason);
            }
            let Some(current) = self.line_snapshot_at_pc()? else {
                break;
            };
            if Some(current.line) != origin.map(|o| o.line) && !current.end_sequence {
                break;
            }
        }
        // We are now at a different line of source code.
        let pc = self
            .process
            .get_pc()?
            .to_file_address(&self.state.elf)
            .ok_or(anyhow!("Failed to get PC as file address"))?;
        let dwarf = self
            .state
            .dwarf
            .as_ref()
            .ok_or(anyhow!("Failed to get dwarf handle"))?;

        // If we've stepped to the very start of a function, we've stepped into
        // it. Skip its prologue by running to the next line-table entry (the
        // first instruction past the stack-setup code).
        let prologue_skip_target = match dwarf.function_containing_address(pc) {
            Some(func_die) if func_die.low_pc()? == pc => {
                match dwarf.get_line_entry_at_address(pc)? {
                    // The iterator is positioned just after the covering entry,
                    // so its first item is the first post-prologue line.
                    Some((_entry, mut after)) => match after.next() {
                        Some(next) => next?.address().to_virt_address(),
                        None => None,
                    },
                    None => None,
                }
            }
            _ => None,
        };
        if let Some(target) = prologue_skip_target {
            return self.process.run_until_address(target);
        }

        Ok(StopReason {
            wait_status: WaitStatus::Stopped(self.process.pid, Signal::SIGTRAP),
            trap_type: Some(TrapType::SingleStep),
            syscall_info: None,
        })
    }

    /// Snapshots the line-table entry covering the current PC into an owned,
    /// borrow-free value, so callers can compare across `&mut self` steps.
    /// `None` when the PC has no covering line entry (the end iterator).
    fn line_snapshot_at_pc(&self) -> Result<Option<LineSnapshot>> {
        Ok(self.line_entry_at_pc()?.map(|entry| LineSnapshot {
            line: (
                entry.address().get(),
                entry.file_index(),
                entry.line(),
                entry.column(),
                entry.discriminator(),
            ),
            end_sequence: entry.end_sequence(),
        }))
    }

    pub fn step_out(&mut self) -> Result<StopReason> {
        todo!()
    }

    pub fn step_over(&mut self) -> Result<StopReason> {
        todo!()
    }

    fn line_entry_at_pc(&self) -> Result<Option<LineTableEntry<'_>>> {
        let pc = self
            .process
            .get_pc()?
            .to_file_address(&self.state.elf)
            .ok_or(anyhow!("Failed to get PC as file address"))?;

        if let Some((entry, _iterator)) = self
            .state
            .dwarf
            .as_ref()
            .ok_or(anyhow!("Failed to get dwarf handle"))?
            .get_line_entry_at_address(pc)?
        {
            return Ok(Some(entry));
        }
        return Ok(None);
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
