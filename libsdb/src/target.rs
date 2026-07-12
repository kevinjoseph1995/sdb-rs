use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::address::FileAddress;
use crate::dwarf::LineTableEntry;
use crate::process::{StopReason, TrapType};
use crate::stack::Stack;
use crate::{address::VirtAddress, dwarf::Dwarf, elf::Elf, process::Process};
use crate::{disassembler, stack};
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

    /// Run the inferior forward until it reaches `target`, treating arrival
    /// there as one clean "unit" of a step-over.
    ///
    /// Returns `Continue(reason)` when the process single-stepped cleanly to
    /// `target` (the step-over loop should keep going), or `Break(reason)` when
    /// it stopped for any other reason — a breakpoint, a signal, an exit, or
    /// landing somewhere other than `target`. In the `Break` case the step-over
    /// is over and `reason` should be handed back to the caller verbatim.
    fn run_over_to(&mut self, target: VirtAddress) -> Result<ControlFlow<StopReason, StopReason>> {
        let reason = self.process.run_until_address(target)?;
        if reason.is_step() && self.process.get_pc()? == target {
            Ok(ControlFlow::Continue(reason))
        } else {
            Ok(ControlFlow::Break(reason))
        }
    }

    /// Step over one source line.
    ///
    /// Like step-in, we advance one machine instruction at a time until the PC
    /// lands on a different source line — but we never descend into callees.
    /// Two things get stepped *over* rather than into:
    ///
    ///   * a `call` instruction, by running to the address of the instruction
    ///     that follows it (where the call will return to), and
    ///   * an inlined function whose body begins at the current PC, by running
    ///     to that inline frame's end (its high PC).
    ///
    /// Anything else is a plain single-instruction step. If the inferior stops
    /// for a reason other than a clean step to where we aimed, we abandon the
    /// step-over and return that stop reason unchanged.
    pub fn step_over(&mut self) -> Result<StopReason> {
        // The line covering the starting PC; we keep stepping until we leave it.
        let origin = self.line_snapshot_at_pc()?;
        loop {
            let outcome = if self.state.stack.get_inline_height() > 0 {
                // The PC sits at the start of an inlined function, so skip its
                // whole body by running to the frame's return address (its high
                // PC). `inline_height` is how many inline frames deep the
                // virtual PC is, so the frame to skip is that many entries up
                // from the innermost one on the stack.
                let inline_stack = self
                    .state
                    .stack
                    .inline_stack_at_pc(&self.state, &self.process)?;
                let frame_to_skip = &inline_stack
                    [inline_stack.len() - self.state.stack.get_inline_height() as usize];
                let return_address = frame_to_skip.high_pc()?.to_virt_address().ok_or(anyhow!(
                    "Failed to get virt_address of return address of inlined function"
                ))?;
                self.run_over_to(return_address)?
            } else {
                // Disassemble the next two instructions: the one about to run,
                // and the one after it (a `call`'s return site). Only reached
                // when not at an inline-frame start, matching the original
                // guard order.
                let instructions = disassembler::disassemble(&self.process, 2, None)?;
                if instructions.len() == 2 && instructions[0].text.starts_with("call") {
                    // Step over the callee by running to the return site.
                    self.run_over_to(instructions[1].address)?
                } else {
                    // An ordinary instruction: just single-step it. There is no
                    // target address to check, so any non-step stop ends here.
                    let reason = self.process.step_instruction()?;
                    if reason.is_step() {
                        ControlFlow::Continue(reason)
                    } else {
                        ControlFlow::Break(reason)
                    }
                }
            };

            // A `Break` means the inferior stopped for something other than the
            // clean step we intended; surface that reason immediately.
            let reason = match outcome {
                ControlFlow::Break(reason) => return Ok(reason),
                ControlFlow::Continue(reason) => reason,
            };

            // Finished once the PC reaches a genuinely different source line. An
            // `end_sequence` row carries no real line, so we step past it, and a
            // PC with no covering line entry at all also ends the walk.
            match self.line_snapshot_at_pc()? {
                None => return Ok(reason),
                Some(current)
                    if Some(current.line) != origin.map(|o| o.line) && !current.end_sequence =>
                {
                    return Ok(reason);
                }
                Some(_) => {}
            }
        }
    }

    pub fn step_out(&mut self) -> Result<StopReason> {
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
