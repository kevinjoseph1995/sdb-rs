use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};

use crate::address::FileAddress;
use crate::disassembler;
use crate::dwarf::{Die, LineTableEntry};
use crate::dwarf_constants::DwTag;
use crate::elf::Elf64_Sym;
use crate::process::{BreakpointId, StopPointId, StopReason, TrapType};
use crate::register_info::RegisterValue;
use crate::stack::Stack;
use crate::{address::VirtAddress, dwarf::Dwarf, elf::Elf, process::Process};
use anyhow::{Context, Result, anyhow};
use libc::AT_ENTRY;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

struct FunctionSearchResult<'dw> {
    dwarf_functions: Vec<Die<'dw>>,
    elf_functions: Vec<(Weak<Elf>, Elf64_Sym)>,
}

enum BreakpointMetadata {
    Function { name: String },
    Line { path: PathBuf, line: usize },
    Address { address: VirtAddress },
}

/// A user-requested breakpoint, e.g. "stop at address X" or (in the future)
/// "stop at line 5 of foo.cpp". A breakpoint is realized by one or more
/// [`crate::process::BreakpointSite`]s, the actual trap-planted addresses in
/// the inferior; today an address breakpoint always has exactly one.
pub struct Breakpoint {
    id: BreakpointId,
    is_hardware: bool,
    /// Whether the user wants this breakpoint armed. Tracked independently of
    /// the underlying sites' own enabled state because two `Breakpoint`s can
    /// share a site (e.g. two function breakpoints resolving to the same
    /// address) and must be independently enable/disable-able: a site stays
    /// physically armed as long as *any* `Breakpoint` referencing it wants it
    /// enabled.
    enabled: bool,
    /// IDs of the breakpoint sites in `Process::breakpoint_sites` that implement this breakpoint.
    site_ids: Vec<StopPointId>,
    metadata: BreakpointMetadata,
}

pub struct TargetState {
    pub elf: Rc<Elf>,
    /// DWARF debug info, or `None` for a binary without a `.debug_info` section.
    pub dwarf: Option<Dwarf>,
    pub stack: Stack,
}

pub struct Target {
    pub process: Process,
    pub state: Rc<TargetState>,
    breakpoints: Vec<Breakpoint>,
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

fn get_next_breakpoint_id() -> BreakpointId {
    static NEXT_ID: std::sync::Mutex<BreakpointId> = std::sync::Mutex::new(0);
    let mut id = NEXT_ID.lock().unwrap();
    let next_id = *id;
    *id += 1;
    next_id
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
        Ok(Target {
            process,
            state,
            breakpoints: Vec::new(),
        })
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
        Ok(Target {
            process,
            state,
            breakpoints: Vec::new(),
        })
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
            // Unlike step-over, step-in descends into callees, so every
            // iteration is a plain single-instruction step — there is no target
            // address to run over. Frame the result the same way step-over does:
            // a clean step is `Continue`, anything else is `Break`.
            let reason = self.process.step_instruction()?;
            let outcome = if reason.is_step() {
                ControlFlow::Continue(reason)
            } else {
                ControlFlow::Break(reason)
            };

            // A `Break` means the inferior stopped for something other than the
            // clean step we intended; surface that reason immediately.
            match outcome {
                ControlFlow::Break(reason) => return Ok(reason),
                ControlFlow::Continue(_) => {}
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

    ///  It should make the process run up until the return address of the currently executing function.
    pub fn step_out(&mut self) -> Result<StopReason> {
        let stack = &self.state.stack;
        let inline_stack = stack.inline_stack_at_pc(&self.state, &self.process)?;
        let has_inline_frames = inline_stack.len() > 1;
        // Short-circuits before the `- 1` below, which would otherwise
        // underflow when `inline_stack` is empty (e.g. no DWARF info at all).
        let is_at_inline_frame =
            has_inline_frames && stack.get_inline_height() < (inline_stack.len() - 1) as u32;
        if is_at_inline_frame {
            let current_frame =
                &inline_stack[inline_stack.len() - stack.get_inline_height() as usize - 1];
            let return_address = current_frame
                .high_pc()?
                .to_virt_address()
                .ok_or(anyhow!("Failed to get return address"))?;
            return self.process.run_until_address(return_address);
        } else {
            let frame_pointer: usize = match self
                .process
                .get_registers()
                .get_register_value(crate::register_info::RegisterId::rbp)?
            {
                RegisterValue::U64(value) => value as usize,
                _ => {
                    return Err(anyhow!("Failed to get register value of rbp"));
                }
            };
            let return_address = VirtAddress {
                address: usize::from_le_bytes(
                    self.process.read_memory(
                        VirtAddress {
                            address: frame_pointer + 8,
                        },
                        8,
                    )?[..8]
                        .try_into()
                        .unwrap(),
                ),
            };
            return self.process.run_until_address(return_address);
        }
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

    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    pub fn find_breakpoint(&self, id: BreakpointId) -> Option<&Breakpoint> {
        self.breakpoints.iter().find(|bp| bp.id == id)
    }

    /// Sets a new breakpoint at `address`, planting a single breakpoint site
    /// there, and returns the new breakpoint's ID.
    pub fn set_address_breakpoint(
        &mut self,
        address: VirtAddress,
        is_hardware: bool,
    ) -> Result<BreakpointId> {
        let id = get_next_breakpoint_id();
        let site_id = self
            .process
            .create_breakpoint_site(address, true, is_hardware, Some(id))?
            .id();
        self.breakpoints.push(Breakpoint {
            id,
            is_hardware,
            enabled: true,
            site_ids: vec![site_id],
            metadata: BreakpointMetadata::Address { address },
        });
        Ok(id)
    }

    pub fn set_function_breakpoint(&mut self, function_name: &str) -> Result<BreakpointId> {
        let is_hardware = false;
        let found = Self::find_functions(&self.state, function_name)?;

        if found.dwarf_functions.is_empty() && found.elf_functions.is_empty() {
            return Err(anyhow!(
                "No function named '{function_name}' found in DWARF or the ELF symbol table"
            ));
        }

        let mut load_addresses = Vec::new();
        if !found.dwarf_functions.is_empty() {
            let dwarf = self
                .state
                .dwarf
                .as_ref()
                .ok_or(anyhow!("Failed to get dwarf handle"))?;
            for die in found.dwarf_functions {
                let Ok(low_pc) = die.low_pc() else {
                    continue;
                };
                // For an inlined subroutine, break at its start; otherwise skip
                // the prologue by breaking at the first line-table row after it.
                let file_address = if die.tag() == Some(DwTag::InlinedSubroutine) {
                    low_pc
                } else {
                    match dwarf.get_line_entry_at_address(low_pc)? {
                        Some((_entry, mut after)) => match after.next() {
                            Some(next) => next?.address(),
                            None => continue,
                        },
                        None => continue,
                    }
                };
                if let Some(load_address) = file_address.to_virt_address() {
                    load_addresses.push(load_address);
                }
            }
        } else {
            for (elf, sym) in found.elf_functions {
                let elf = elf.upgrade().ok_or(anyhow!("Elf handle no longer alive"))?;
                let file_address = FileAddress::new(&elf, sym.st_value as usize);
                if let Some(load_address) = file_address.to_virt_address() {
                    load_addresses.push(load_address);
                }
            }
        }

        let id = get_next_breakpoint_id();
        let mut site_ids = Vec::new();
        for load_address in load_addresses {
            // Two breakpoints (e.g. two independent `set_function_breakpoint`
            // calls on the same function) can resolve to the same address; a
            // process-level site can only be planted once per address, so
            // share the existing site rather than dropping this breakpoint's
            // claim on it.
            let site_id = match self
                .process
                .breakpoint_sites
                .iter()
                .find(|site| site.virtual_address() == load_address)
            {
                Some(existing) => existing.id(),
                None => self
                    .process
                    .create_breakpoint_site(load_address, true, is_hardware, Some(id))?
                    .id(),
            };
            site_ids.push(site_id);
        }

        if site_ids.is_empty() {
            return Err(anyhow!(
                "Could not resolve a load address for function '{function_name}'"
            ));
        }

        self.breakpoints.push(Breakpoint {
            id,
            is_hardware,
            enabled: true,
            site_ids,
            metadata: BreakpointMetadata::Function {
                name: function_name.to_string(),
            },
        });
        Ok(id)
    }

    pub fn set_line_breakpoint(
        &mut self,
        filepath: &Path,
        line_number: usize,
    ) -> Result<BreakpointId> {
        todo!()
    }

    pub fn remove_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        let position = self
            .breakpoints
            .iter()
            .position(|bp| bp.id == id)
            .ok_or_else(|| anyhow!("Breakpoint with ID {} not found", id))?;
        let site_ids = self.breakpoints[position].site_ids.clone();
        self.breakpoints.remove(position);
        for site_id in site_ids {
            // A site can be shared with another breakpoint (e.g. two function
            // breakpoints resolving to the same address); only tear it down
            // once nothing else references it.
            if !self.site_in_use(site_id) {
                self.process.remove_breakpoint_by_id(site_id)?;
            }
        }
        Ok(())
    }

    pub fn enable_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        let position = self
            .breakpoints
            .iter()
            .position(|bp| bp.id == id)
            .ok_or_else(|| anyhow!("Breakpoint with ID {} not found", id))?;
        self.breakpoints[position].enabled = true;
        for site_id in self.breakpoints[position].site_ids.clone() {
            self.process.enable_breakpoint_by_id(site_id)?;
        }
        Ok(())
    }

    pub fn disable_breakpoint(&mut self, id: BreakpointId) -> Result<()> {
        let position = self
            .breakpoints
            .iter()
            .position(|bp| bp.id == id)
            .ok_or_else(|| anyhow!("Breakpoint with ID {} not found", id))?;
        self.breakpoints[position].enabled = false;
        for site_id in self.breakpoints[position].site_ids.clone() {
            // Leave the underlying site armed if some other, still-enabled
            // breakpoint also depends on it.
            if !self.site_wanted_enabled_by_other(site_id, id) {
                self.process.disable_breakpoint_by_id(site_id)?;
            }
        }
        Ok(())
    }

    /// Whether the user has this breakpoint enabled. Tracked independently of
    /// the underlying sites' state since a site can be shared with another,
    /// independently enabled/disabled breakpoint.
    pub fn is_breakpoint_enabled(&self, id: BreakpointId) -> Result<bool> {
        let bp = self
            .find_breakpoint(id)
            .ok_or_else(|| anyhow!("Breakpoint with ID {} not found", id))?;
        Ok(bp.enabled)
    }

    fn site_in_use(&self, site_id: StopPointId) -> bool {
        self.breakpoints
            .iter()
            .any(|bp| bp.site_ids.contains(&site_id))
    }

    fn site_wanted_enabled_by_other(&self, site_id: StopPointId, excluding: BreakpointId) -> bool {
        self.breakpoints
            .iter()
            .any(|bp| bp.id != excluding && bp.enabled && bp.site_ids.contains(&site_id))
    }

    /// The virtual address of each site backing `id`.
    pub fn breakpoint_addresses(&self, id: BreakpointId) -> Result<Vec<VirtAddress>> {
        let bp = self
            .find_breakpoint(id)
            .ok_or_else(|| anyhow!("Breakpoint with ID {} not found", id))?;
        Ok(self.addresses_of(bp))
    }

    /// The virtual address of each site backing `bp`. Prefer this over
    /// [`Target::breakpoint_addresses`] when the caller already holds a
    /// `&Breakpoint` (e.g. from iterating [`Target::breakpoints`]), to skip
    /// re-scanning `self.breakpoints` for the ID.
    pub fn addresses_of(&self, bp: &Breakpoint) -> Vec<VirtAddress> {
        bp.site_ids
            .iter()
            .filter_map(|site_id| {
                self.process
                    .breakpoint_sites
                    .iter()
                    .find(|s| s.id() == *site_id)
                    .map(|s| s.virtual_address())
            })
            .collect()
    }

    /// Takes `&TargetState` rather than `&self` so that, at call sites, the
    /// returned `Die`s (which borrow from `state.dwarf`) don't lock down the
    /// whole `Target` — callers still need `&mut self.process` afterwards to
    /// plant breakpoint sites at the addresses found here.
    fn find_functions<'dw>(state: &'dw TargetState, name: &str) -> Result<FunctionSearchResult<'dw>> {
        let dwarf_found = state
            .dwarf
            .as_ref()
            .map(|dwarf| dwarf.find_functions(name))
            .unwrap_or_default();

        if dwarf_found.is_empty() {
            let name = std::ffi::CString::new(name).context("Function name contains a nul byte")?;
            let elf_functions = state
                .elf
                .get_symbols_with_name(&name)
                .into_iter()
                .map(|sym| (Rc::downgrade(&state.elf), *sym))
                .collect();
            Ok(FunctionSearchResult {
                dwarf_functions: Vec::new(),
                elf_functions,
            })
        } else {
            Ok(FunctionSearchResult {
                dwarf_functions: dwarf_found,
                elf_functions: Vec::new(),
            })
        }
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

impl Breakpoint {
    pub fn id(&self) -> BreakpointId {
        self.id
    }

    pub fn is_hardware(&self) -> bool {
        self.is_hardware
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn site_ids(&self) -> &[StopPointId] {
        &self.site_ids
    }

    /// Human-readable description of what this breakpoint was set on, e.g.
    /// `function 'main'`, `foo.cpp:10`, or `address 0x1234`.
    pub fn description(&self) -> String {
        match &self.metadata {
            BreakpointMetadata::Function { name } => format!("function '{}'", name),
            BreakpointMetadata::Line { path, line } => format!("{}:{}", path.display(), line),
            BreakpointMetadata::Address { address } => format!("address {}", address),
        }
    }
}
