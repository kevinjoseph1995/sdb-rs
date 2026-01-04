/////////////////////////////////////////
use std::ffi::CString;
use std::fmt::Display;
use std::path::PathBuf;
/////////////////////////////////////////
use anyhow::{Context, Result, anyhow};
use core::panic;
use libc::SI_KERNEL;
use libc::TRAP_HWBKPT;
use libc::TRAP_TRACE;
use libc::c_long;
use libc::personality;
use libc::user;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::ptrace::attach;
use nix::sys::ptrace::traceme;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::sys::uio::RemoteIoVec;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
use nix::sys::wait::waitpid;
use nix::unistd::ForkResult;
use nix::unistd::dup2_stdout;
use nix::unistd::execvp;
use nix::unistd::fork;
use syscalls::Sysno;
/////////////////////////////////////////
use crate::pipe_channel;
use crate::register_info;
use crate::register_info::RegisterFormat;
use crate::register_info::RegisterInfo;
use crate::register_info::RegisterType;
use crate::register_info::RegisterValue;

type Pid = nix::unistd::Pid;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ProcessHandleState {
    Running,
    Stopped,
    Exited,
    Terminated,
}

#[derive(PartialEq, Debug)]
pub enum ProcessState {
    Running,        // Running
    Sleeping,       // Sleeping in an interruptible wait
    Waiting,        // Waiting in uninterruptible disk sleep
    Zombie,         // Zombie
    Stopped,        // Stopped on a signal.
    TracingStopped, // Tracing stopped
    Unknown(char),
}

#[derive(Debug, PartialEq)]
pub enum TrapType {
    SoftwareBreakpoint,
    HardwareBreakpoint,
    SingleStep,
    Syscall,
}

#[derive(Debug, Clone)]
pub enum SyscallCatchPolicyMode {
    None,             // No syscalls are caught
    All,              // All syscalls are caught
    Some(Vec<Sysno>), // Only the specified syscalls are caught
}

impl PartialEq for SyscallCatchPolicyMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SyscallCatchPolicyMode::None, SyscallCatchPolicyMode::None) => true,
            (SyscallCatchPolicyMode::All, SyscallCatchPolicyMode::All) => true,
            (SyscallCatchPolicyMode::Some(a), SyscallCatchPolicyMode::Some(b)) => {
                a.len() == b.len() && a.iter().all(|item| b.contains(item))
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub enum SyscallMetadata {
    EntryArgs([u64; 6]),
    ExitReturnValue(i64),
}

#[derive(Debug)]
pub struct SyscallInformation {
    pub number: u16,
    pub entry: bool,
    pub metadata: SyscallMetadata,
}

#[derive(Debug)]
pub struct StopReason {
    pub wait_status: WaitStatus,
    pub trap_type: Option<TrapType>,
    pub syscall_info: Option<SyscallInformation>,
}

impl From<char> for ProcessState {
    fn from(value: char) -> Self {
        match value {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'D' => ProcessState::Waiting,
            'Z' => ProcessState::Zombie,
            'T' => ProcessState::Stopped,
            't' => ProcessState::TracingStopped,
            ch => ProcessState::Unknown(ch),
        }
    }
}

pub struct Process {
    pub pid: Pid,
    terminate_on_end: bool,
    state: ProcessHandleState,
    read_port: Option<pipe_channel::ReadPort>,
    is_attached: bool,
    registers: Registers,
    executable_path: Option<PathBuf>,
    args: Option<String>,
    syscall_catch_policy: SyscallCatchPolicyMode,
    expecting_syscall_exit: bool,
    pub breakpoints: Vec<Breakpoint>,
    pub watchpoints: Vec<Watchpoint>,
}

impl Process {
    fn set_ptrace_options(pid: Pid) -> Result<()> {
        nix::sys::ptrace::setoptions(pid, nix::sys::ptrace::Options::PTRACE_O_TRACESYSGOOD)
            .context("Failed to set ptrace options")?;
        Ok(())
    }

    /// Attaches to an existing process for debugging.
    pub fn attach(pid: Pid) -> Result<Self> {
        attach(pid).context("Failed to attach to process")?; // The tracee is sent a SIGSTOP, but will not necessarily have stopped by the completion of this call.
        let mut child_process_handle = Process {
            pid,
            terminate_on_end: false,
            state: ProcessHandleState::Stopped,
            read_port: None,
            is_attached: true,
            registers: Registers::new(),
            executable_path: None,
            args: None,
            syscall_catch_policy: SyscallCatchPolicyMode::None,
            expecting_syscall_exit: false,
            breakpoints: Vec::new(),
            watchpoints: Vec::new(),
        };
        let _stop_reason = child_process_handle.wait_on_signal(None)?;
        Self::set_ptrace_options(pid)?;
        Ok(child_process_handle)
    }

    /// Launches a new inferior process for debugging.
    /// This function forks the current process and sets up the child process for debugging.
    /// It enables tracing for the child process and loads the executable into it.
    pub fn launch(
        executable_path: &PathBuf,
        args: Option<String>,
        debug_process_being_launched: bool,
        stdout_replacement: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self> {
        let (read_port, write_port) = pipe_channel::create_pipe_channel(true)?;
        match unsafe { fork() }? {
            ForkResult::Parent { child, .. } => {
                drop(write_port);
                let mut child_process_handle = Process {
                    pid: child,
                    terminate_on_end: true,
                    state: ProcessHandleState::Stopped,
                    read_port: None,
                    is_attached: debug_process_being_launched,
                    registers: Registers::new(),
                    executable_path: Some(executable_path.clone()),
                    syscall_catch_policy: SyscallCatchPolicyMode::None,
                    args: args.clone(),
                    expecting_syscall_exit: false,
                    breakpoints: Vec::new(),
                    watchpoints: Vec::new(),
                };
                println!("Launching process with PID: {}", child_process_handle.pid);
                if debug_process_being_launched {
                    // If we are debugging the process being launched, we need to wait for it to stop.
                    // traceme() is called in the child process, so we need to wait for it to stop.
                    match child_process_handle.wait_on_signal(None)?.wait_status {
                        WaitStatus::Exited(_, exit_code) => {
                            let mut error_message =
                                format!("Child process exited with exit code: {} . ", exit_code);
                            if let Ok(message) = read_port.read() {
                                if let Ok(message) = String::from_utf8(message) {
                                    error_message = format!("{error_message} {message}")
                                }
                            }
                            child_process_handle.state = ProcessHandleState::Exited;
                            return Err(anyhow!("{}", error_message));
                        }
                        WaitStatus::Signaled(_, signal, _) => {
                            let mut error_message: String =
                                format!("Child process terminated by signal: {} . ", signal);
                            if let Ok(message) = read_port.read() {
                                if let Ok(message) = String::from_utf8(message) {
                                    error_message = format!("{error_message} {message}")
                                }
                            }
                            child_process_handle.state = ProcessHandleState::Terminated;
                            return Err(anyhow!("{}", error_message));
                        }
                        WaitStatus::Stopped(_, _) => {
                            child_process_handle.state = ProcessHandleState::Stopped;
                        }
                        WaitStatus::Continued(_) => {
                            child_process_handle.state = ProcessHandleState::Running;
                        }
                        _ => {}
                    }
                    Self::set_ptrace_options(child_process_handle.pid)?;
                }
                child_process_handle.read_port = Some(read_port);
                Ok(child_process_handle)
            }
            ForkResult::Child => {
                drop(read_port);
                if let Some(stdout_replacement) = stdout_replacement {
                    // Redirect stdout to the provided file descriptor
                    dup2_stdout(stdout_replacement)?;
                }
                let result =
                    setup_child_process(executable_path, args, debug_process_being_launched);
                if let Err(e) = result {
                    write_port
                        .write_from_buffer(format!("Error: {}\n", e).as_bytes())
                        .expect("Failed to write error message to pipe");
                    std::process::exit(1);
                }
                unreachable!(); // execvp replaces the child process, so this line should never be reached
            }
        }
    }

    pub fn exists(&self) -> bool {
        process_with_pid_exists(self.pid)
    }

    /// Sets the program counter (PC) register to the specified address.
    fn set_pc(&mut self, address: VirtAddress) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to set program counter (PC) register"
        );
        let address: usize = address.into();
        self.write_register_value(
            register_info::RegisterId::rip,
            RegisterValue::U64(address as u64),
        )
        .context("Failed to set program counter (PC) register")?;
        Ok(())
    }

    pub fn get_pc(&self) -> Result<VirtAddress> {
        assert!(
            self.is_attached,
            "Process must be attached to get program counter (PC) register"
        );
        let pc_value = self
            .registers
            .get_register_value(register_info::RegisterId::rip)
            .context("Failed to get program counter (PC) register")?;
        match pc_value {
            RegisterValue::U64(pc) => Ok(VirtAddress::from(pc as usize)),
            _ => Err(anyhow!(
                "Unexpected register value type for PC: {:?}",
                pc_value
            )),
        }
    }

    pub fn get_current_hardware_stoppoint(&self) -> Result<HardwareStopPointId> {
        assert!(
            self.is_attached,
            "Process must be attached to get current hardware stop point"
        );
        assert!(
            self.state == ProcessHandleState::Stopped,
            "Process must be stopped to get current hardware stop point"
        );
        /* DR6 Debug status register:
        The least significant 4 bits of the status register (DR6) correspond to each of these registers in turn.
        If code triggers a hardware breakpoint for one of those addresses, the relevant bit in DR6 will be set to 1.
        For example, triggering the breakpoint for the address held in DR2 would set the third bit in DR6.
        */
        let status = match self
            .get_registers()
            .get_register_value(register_info::RegisterId::dr(6))
            .context("Failed to get DR6 register")?
        {
            RegisterValue::U64(value) => value,
            _ => {
                return Err(anyhow!("Unexpected register value type for DR6",));
            }
        };
        if status & 0b1111 == 0 {
            return Err(anyhow!("No hardware stop point triggered"));
        }
        // Find the first set bit in the status register.
        let triggered_index = status.trailing_zeros() as u32;
        if triggered_index >= 4 {
            return Err(anyhow!(
                "Triggered index out of bounds: {}",
                triggered_index
            ));
        }
        // The triggered index corresponds to the debug register that was triggered.
        let debug_register_id = register_info::RegisterId::dr(triggered_index);
        let address = match self
            .get_registers()
            .get_register_value(debug_register_id)
            .context("Failed to get debug register value")?
        {
            RegisterValue::U64(value) => VirtAddress::from(value as usize),
            _ => {
                return Err(anyhow!(
                    "Unexpected register value type for debug register: {:?}",
                    debug_register_id
                ));
            }
        };
        // Check if it is a hardware stop point or a watchpoint.
        for watchpoint in self.watchpoints.iter() {
            if watchpoint.virtual_address == address {
                return Ok(HardwareStopPointId::WatchpointId(watchpoint.id));
            }
        }
        for breakpoint in self.breakpoints.iter() {
            if breakpoint.virtual_address == address && breakpoint.is_hardware {
                return Ok(HardwareStopPointId::HardwareStopPointId(breakpoint.id));
            }
        }
        panic!(
            "No hardware stop point or watchpoint found for address: {}",
            address
        );
    }

    pub fn get_registers(&self) -> &Registers {
        return &self.registers;
    }

    pub fn get_trap_reason(&self) -> Result<Option<TrapType>> {
        assert!(
            self.is_attached,
            "Process must be attached to get trap reason"
        );
        let siginfo = nix::sys::ptrace::getsiginfo(self.pid)?;

        match siginfo.si_code {
            TRAP_TRACE => Ok(Some(TrapType::SingleStep)),
            SI_KERNEL => Ok(Some(TrapType::SoftwareBreakpoint)), // Linux kernel uses SI_KERNEL for software breakpoints
            TRAP_HWBKPT => Ok(Some(TrapType::HardwareBreakpoint)),
            _ => Ok(None),
        }
    }

    fn construct_stop_reason(&mut self, wait_status: WaitStatus) -> Result<StopReason> {
        let trap_type = if let WaitStatus::Stopped(_pid, _signal) = &wait_status {
            self.get_trap_reason()?
        } else {
            None
        };
        Ok(StopReason {
            wait_status,
            trap_type,
            syscall_info: None, // Syscall information handling can be added here later
        })
    }

    pub fn set_syscall_catch_policy(&mut self, policy: SyscallCatchPolicyMode) {
        self.syscall_catch_policy = policy;
    }

    fn augment_stop_reason_with_syscall_info(
        &mut self,
        mut stop_reason: StopReason,
    ) -> Result<StopReason> {
        if let WaitStatus::PtraceSyscall(_pid) = stop_reason.wait_status {
            stop_reason.trap_type = Some(TrapType::Syscall);
            stop_reason.wait_status = WaitStatus::Stopped(self.pid, Signal::SIGTRAP); // Convert to Stopped status for consistency
            let id = match self
                .registers
                .get_register_value(register_info::RegisterId::orig_rax)?
            {
                RegisterValue::U64(value) => value as u16,
                _ => {
                    return Err(anyhow!("Unexpected register value type for orig_rax",));
                }
            };
            if self.expecting_syscall_exit {
                // Handle syscall exit
                let return_value: i64 = match self
                    .registers
                    .get_register_value(register_info::RegisterId::rax)?
                {
                    RegisterValue::U64(u64_value) => i64::from_le_bytes(u64_value.to_le_bytes()),
                    _ => {
                        return Err(anyhow!("Unexpected register value type for rax",));
                    }
                };
                stop_reason.syscall_info = Some(SyscallInformation {
                    number: id,
                    entry: false,
                    metadata: SyscallMetadata::ExitReturnValue(return_value),
                });
                self.expecting_syscall_exit = false;
            } else {
                // Handle syscall entry
                self.expecting_syscall_exit = true;
                // https://man7.org/linux/man-pages/man2/syscall.2.html
                // See the system call interface for x86_64 Linux for argument registers
                // Arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7
                // x86-64        rdi   rsi   rdx   r10   r8    r9    -
                const ARG_REGISTERS: [register_info::RegisterId; 6] = [
                    register_info::RegisterId::rdi,
                    register_info::RegisterId::rsi,
                    register_info::RegisterId::rdx,
                    register_info::RegisterId::r10,
                    register_info::RegisterId::r8,
                    register_info::RegisterId::r9,
                ];
                let mut args: [u64; 6] = [0; 6];
                for (i, reg_id) in ARG_REGISTERS.iter().enumerate() {
                    args[i] = match self.registers.get_register_value(*reg_id)? {
                        RegisterValue::U64(value) => value,
                        _ => {
                            return Err(anyhow!(
                                "Unexpected register value type for syscall argument register: {:?}",
                                reg_id
                            ));
                        }
                    };
                }
                stop_reason.syscall_info = Some(SyscallInformation {
                    number: id,
                    entry: true,
                    metadata: SyscallMetadata::EntryArgs(args),
                });
            }
        } else {
            // Not a syscall stop
            self.expecting_syscall_exit = false; // Reset the flag if we are not in a syscall stop
        }
        Ok(stop_reason)
    }

    fn maybe_resume_from_syscall_stop(&mut self, stop_reason: StopReason) -> Result<StopReason> {
        debug_assert!(
            self.is_attached,
            "Process must be attached to resume from syscall stop"
        );
        debug_assert!(
            self.state == ProcessHandleState::Stopped,
            "Process must be stopped to resume from syscall stop"
        );
        match (&self.syscall_catch_policy, &stop_reason.syscall_info) {
            (SyscallCatchPolicyMode::Some(to_catch), Some(syscall_info)) => {
                if !to_catch.contains(&(Sysno::from(syscall_info.number as i32))) {
                    // Resume the process if we are not catching this syscall
                    self.resume_process()
                        .context("Failed to resume process from syscall stop")?;
                    // Wait for the next stop
                    return self.wait_on_signal(None); // This is a recursive call
                }
            }
            _ => {
                // No-op
            }
        }
        Ok(stop_reason)
    }

    /// Waits for the process to stop or exit. This function blocks until the process undergoes a state change.
    pub fn wait_on_signal(&mut self, options: Option<WaitPidFlag>) -> Result<StopReason> {
        let stop_reason = self.construct_stop_reason(
            waitpid(self.pid, options).context("Failed to wait for process")?,
        )?;
        match &stop_reason.wait_status {
            WaitStatus::Exited(_, _) => {
                self.state = ProcessHandleState::Exited;
            }
            WaitStatus::Signaled(_pid, _signal, _) => {
                self.state = ProcessHandleState::Terminated;
            }
            WaitStatus::Stopped(_, _) | WaitStatus::PtraceSyscall(_) => {
                self.state = ProcessHandleState::Stopped;
            }
            WaitStatus::Continued(_) => {
                self.state = ProcessHandleState::Running;
            }
            _ => {}
        }
        if self.is_attached && self.state == ProcessHandleState::Stopped {
            self.read_all_registers()
                .context("Failed to read registers after waiting for process")?;
        }
        let mut stop_reason = self.augment_stop_reason_with_syscall_info(stop_reason)?;
        if let WaitStatus::Stopped(_, Signal::SIGTRAP) = stop_reason.wait_status {
            // When the process stops due to a SIGTRAP, it is likely due to a breakpoint or single-step.
            let instruction_begin = self.get_pc()? - VirtAddress::new(1usize);
            if self
                .breakpoints
                .iter()
                .find(|bp| bp.virtual_address == instruction_begin && bp.is_enabled)
                .is_some()
            {
                // If the breakpoint is enabled at the instruction address, we need to set the PC to the instruction address.
                self.set_pc(instruction_begin)?;
            } else if stop_reason.trap_type == Some(TrapType::HardwareBreakpoint) {
                if let HardwareStopPointId::WatchpointId(watchpoint_id) =
                    self.get_current_hardware_stoppoint()?
                {
                    let index = self
                        .watchpoints
                        .iter()
                        .position(|wp| wp.id == watchpoint_id)
                        .expect("Watchpoint not found");
                    self.update_watchpoint_data(index)?;
                }
            } else if stop_reason.trap_type == Some(TrapType::Syscall) {
                stop_reason = self.maybe_resume_from_syscall_stop(stop_reason)?;
            }
        }
        Ok(stop_reason)
    }

    pub fn restart_process(&mut self) -> Result<()> {
        debug_assert!(
            self.state == ProcessHandleState::Exited,
            "Process must be exited to restart"
        );
        debug_assert!(
            self.executable_path.is_some(),
            "Executable path must be set to restart process"
        );
        let old_syscall_policy = self.syscall_catch_policy.clone();
        *self = Process::launch(
            self.executable_path
                .as_ref()
                .expect("Executable path must be set to restart process"),
            self.args.clone(),
            true,
            None, /*No stdout replacement */
        )?;
        self.syscall_catch_policy = old_syscall_policy;
        Ok(())
    }

    /// Resumes the execution of the process being debugged.
    pub fn resume_process(&mut self) -> Result<()> {
        let pc = self
            .get_pc()
            .context("Failed to get program counter (PC) register")?;
        // If the breakpoint at PC is enabled, we need to disable it before resuming.
        if let Some(index) = self
            .breakpoints
            .iter()
            .position(|bp| bp.virtual_address == pc && bp.is_enabled)
        {
            // Disable the breakpoint at PC, step over the int3 instruction, and then re-enable it.
            // This is necessary to avoid hitting the breakpoint again immediately after resuming.
            self.disable_breakpoint_at_index(index)?;
            ptrace::step(self.pid, None).context("Failed to step process")?; // Step over the int3 instruction.
            waitpid(self.pid, None).context("Failed to wait for process after stepping")?;
            self.enable_breakpoint_at_index(index)
                .context("Failed to re-enable breakpoint after stepping")?;
        }

        if self.syscall_catch_policy == SyscallCatchPolicyMode::None {
            if let Err(e) = nix::sys::ptrace::cont(self.pid, None) {
                eprintln!("Failed to resume process: {}", e);
                return Err(e.into());
            }
        } else {
            if let Err(e) = nix::sys::ptrace::syscall(self.pid, None) {
                eprintln!("Failed to resume process with syscall tracing: {}", e);
                return Err(e.into());
            }
        }
        self.state = ProcessHandleState::Running;
        Ok(())
    }

    pub fn single_step(&mut self) -> Result<StopReason> {
        assert!(self.is_attached, "Process must be attached to single step");

        let mut breakpoint_to_reenable: Option<usize> = None;
        let program_counter = self.get_pc()?;
        if let Some(breakpoint_site_index) = self
            .breakpoints
            .iter()
            .position(|bp| bp.virtual_address == program_counter)
        {
            let breakpoint = &mut self.breakpoints[breakpoint_site_index];
            if breakpoint.is_enabled {
                // If the breakpoint is enabled at the instruction address, we need to disable it before single stepping.
                self.disable_breakpoint_at_index(breakpoint_site_index)?;
                breakpoint_to_reenable = Some(breakpoint_site_index);
            }
        }
        nix::sys::ptrace::step(self.pid, None).context("Failed to step process")?;
        let reason = self.wait_on_signal(None)?;
        // Re-enable the breakpoint if it was enabled before the single step.
        if let Some(breakpoint_site_index) = breakpoint_to_reenable {
            self.enable_breakpoint_at_index(breakpoint_site_index)
                .context("Failed to re-enable breakpoint after single step")?;
        }
        Ok(reason)
    }

    pub fn stop_process(&mut self) -> Result<()> {
        if self.state == ProcessHandleState::Running {
            kill(self.pid, Signal::SIGSTOP).context("Failed to stop process")?;
            self.state = ProcessHandleState::Stopped;
            self.wait_on_signal(None)
                .context("Failed to wait for process")?;
        }
        self.state = ProcessHandleState::Stopped;
        Ok(())
    }

    pub fn print_child_output(&mut self) -> Result<()> {
        if let Some(read_port) = &self.read_port {
            let output = read_port.read()?;
            print!("{}", String::from_utf8_lossy(&output));
        }
        Ok(())
    }

    pub fn write_register_value(
        &mut self,
        register_id: register_info::RegisterId,
        value: RegisterValue,
    ) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to write registers"
        );
        let register_info = register_info::get_register_info(register_id)
            .ok_or_else(|| anyhow!("Failed to get register info for {:?}", register_id))?;
        self.registers.set_register_value(register_info, value)?;
        if register_info.reg_type == RegisterType::FloatingPoint {
            // Floating point registers are written as a whole struct.
            self.write_fprs(&self.registers.data.i387)
                .context("Failed to write floating point registers")?;
        } else {
            // For general purpose registers, we write them one by one.
            let aligned_offset = register_info.offset & !0b111;
            let value: u64 = register_info::coerce_bytes_of_struct_to_type_at_offset::<user, u64>(
                &self.registers.data,
                aligned_offset,
            )?;
            self.poke_user_data(aligned_offset, value)?;
        }
        Ok(())
    }

    pub fn write_memory(&self, start: VirtAddress, data: &[u8]) -> Result<()> {
        assert!(self.is_attached, "Process must be attached to write memory");
        let mut written = 0usize;
        while written < data.len() {
            let remaining_bytes = &data[written..];
            let eight_byte_chunk: [u8; 8] = {
                if remaining_bytes.len() > 8 {
                    let mut chunk = [0u8; 8];
                    chunk.copy_from_slice(&remaining_bytes[0..8]);
                    chunk
                } else {
                    let mut chunk = [0u8; 8];
                    let read_memory = self.read_memory(start + written, 8)?;
                    chunk.copy_from_slice(&read_memory[0..8]); // Copy the existing memory to the chunk
                    chunk[0..remaining_bytes.len()].copy_from_slice(remaining_bytes); // Copy the new data to the first part
                    chunk
                }
            };
            ptrace::write(
                self.pid,
                (start + written).get() as *mut std::ffi::c_void,
                i64::from_le_bytes(eight_byte_chunk),
            )
            .context("Failed to write memory")?;

            written += 8;
        }

        Ok(())
    }

    pub fn get_state(&self) -> ProcessHandleState {
        self.state
    }

    /// Reads the memory of the process being debugged.
    /// This function reads the memory of the process using the `process_vm_readv` system call.
    /// The memory is read in chunks that are page aligned.
    /// The number of bytes returned may be less than the number of bytes requested.
    pub fn read_memory(&self, start: VirtAddress, num_bytes: usize) -> Result<Vec<u8>> {
        assert!(self.is_attached, "Process must be attached to read memory");
        // Setup remote descriptors. Split the read into chunks that are page aligned.
        // Each chunk can have a maximum size of 4096 bytes(which is the default page size of x64 Linux).
        let remote_iovs: Vec<RemoteIoVec> = {
            let mut remote_iovs = vec![];
            let mut start = start;
            let mut num_bytes = num_bytes;
            while num_bytes > 0 {
                let next_page_boundary = start.next_page_boundary();
                let chunk_size = std::cmp::min(num_bytes, (next_page_boundary - start).get());
                remote_iovs.push(RemoteIoVec {
                    base: start.get(),
                    len: chunk_size,
                });
                start = start + chunk_size;
                num_bytes -= chunk_size;
            }
            remote_iovs
        };
        let mut buffer_to_return = vec![0u8; num_bytes];
        let total_number_of_bytes_read = nix::sys::uio::process_vm_readv(
            self.pid,
            &mut [std::io::IoSliceMut::new(&mut buffer_to_return)],
            &remote_iovs,
        )
        .context("Failed to read memory")?;
        assert!(total_number_of_bytes_read <= num_bytes);
        buffer_to_return.resize(total_number_of_bytes_read, 0);
        Ok(buffer_to_return)
    }

    /// Reads the memory of the process being debugged. Filters all the int3 instructions
    /// and replaces them with the original data from the breakpoint sites.
    pub fn read_memory_without_breakpoint_traps(
        &self,
        start: VirtAddress,
        num_bytes: usize,
    ) -> Result<Vec<u8>> {
        let mut bytes = self.read_memory(start, num_bytes)?;
        for breakpoint in self.breakpoints.iter() {
            if breakpoint.is_hardware || !breakpoint.is_enabled {
                continue; // Skip hardware breakpoints and disabled breakpoints
            }
            let break_point_address = breakpoint.virtual_address;
            if break_point_address >= start && break_point_address < start + num_bytes {
                let offset = break_point_address - start;
                bytes[offset.get()] = breakpoint
                    .saved_data
                    .expect("Breakpoint data should be present");
            }
        }
        Ok(bytes)
    }

    pub fn read_all_registers(&mut self) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to read registers"
        );
        self.registers.data.regs = nix::sys::ptrace::getregs(self.pid)
            .context("Failed to read general purpose  registers")?;
        self.registers.data.i387 =
            nix::sys::ptrace::getregset::<nix::sys::ptrace::regset::NT_PRFPREG>(self.pid)
                .context("Failed to read floating point registers")?;
        for debug_register_index in 0..8usize {
            let offset = register_info::get_register_info(register_info::RegisterId::dr(
                debug_register_index as u32,
            ))
            .ok_or(anyhow!(
                "Failed to get debug register info for index {}",
                debug_register_index
            ))?
            .offset;
            self.registers.data.u_debugreg[debug_register_index] =
                nix::sys::ptrace::read_user(self.pid, offset as *mut std::ffi::c_void).context(
                    format!("Failed to read debug register {}", debug_register_index),
                )? as u64;
        }
        Ok(())
    }

    fn poke_user_data(&self, offset: usize, value: u64) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to poke user data"
        );
        nix::sys::ptrace::write_user(self.pid, offset as *mut std::ffi::c_void, value as i64)
            .context("Failed to poke user data")?;
        Ok(())
    }

    fn write_fprs(&self, fprs: &libc::user_fpregs_struct) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to write floating point registers"
        );
        nix::sys::ptrace::setregset::<nix::sys::ptrace::regset::NT_PRFPREG>(self.pid, fprs.clone())
            .context("Failed to write floating point registers")?;
        Ok(())
    }

    // Maybe unused
    #[allow(dead_code)]
    fn write_gprs(&self, gprs: &libc::user_regs_struct) {
        assert!(
            self.is_attached,
            "Process must be attached to write floating point registers"
        );
        nix::sys::ptrace::setregs(self.pid, gprs.clone())
            .expect("Failed to write general purpose registers");
    }

    pub fn create_watchpoint<'a>(
        &'a mut self,
        address: VirtAddress,
        size: u8,
        mode: StopPointMode,
        enable_after_creation: bool,
    ) -> Result<&'a mut Watchpoint> {
        if self
            .watchpoints
            .iter()
            .any(|wp| wp.virtual_address == address)
        {
            return Err(anyhow!(
                "Watchpoint site already exists at address: {}",
                address
            ));
        }
        self.watchpoints.push(Watchpoint::new(address, mode, size)?);
        let index = self.watchpoints.len() - 1;
        if enable_after_creation {
            self.enable_watchpoint_at_index(index)
                .context("Failed to enable watchpoint after creation")?;
        }
        self.update_watchpoint_data(index)
            .context("Failed to update watchpoint data after enabling")?;
        Ok(self.watchpoints.last_mut().unwrap())
    }

    fn update_watchpoint_data(&mut self, index: usize) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to update watchpoint data"
        );
        let watchpoint_address = self.watchpoints[index].virtual_address;
        let watchpoint_size = self.watchpoints[index].size as usize;
        let current_data = self
            .read_memory(watchpoint_address, watchpoint_size)
            .context("Failed to read watchpoint data")?;
        if current_data.len() != watchpoint_size {
            return Err(anyhow!(
                "Watchpoint size mismatch: expected {}, got {}",
                watchpoint_size,
                current_data.len()
            ));
        }
        // current_data.len() can be less than 8 bytes, so we need to handle that.
        // We will convert the current_data to a u64, filling with zeros if necessary.
        let mut data = [0u8; 8];
        data[..current_data.len()].copy_from_slice(&current_data); // Least significant bytes first, most significant bytes zeroed-> Little Endian
        self.watchpoints[index].previous_data = self.watchpoints[index].data;
        self.watchpoints[index].data = Some(u64::from_le_bytes(
            data.try_into().expect("Invalid watchpoint data length"),
        ));
        Ok(())
    }

    fn enable_watchpoint_at_index(&mut self, index: usize) -> Result<()> {
        if self.watchpoints[index].is_enabled {
            return Ok(()); // Watchpoint is already enabled, no action needed
        }
        let hardware_index = self.set_hardware_breakpoint(
            self.watchpoints[index].virtual_address,
            self.watchpoints[index].size as usize,
            self.watchpoints[index].mode,
        )?;
        self.watchpoints[index].hardware_index = Some(hardware_index);
        self.watchpoints[index].is_enabled = true;
        Ok(())
    }

    fn disable_watchpoint_at_index(&mut self, index: usize) -> Result<()> {
        if !self.watchpoints[index].is_enabled {
            return Ok(()); // Watchpoint is already disabled, no action needed
        }
        self.clear_hardware_breakpoint(self.watchpoints[index].hardware_index.unwrap())?;
        self.watchpoints[index].hardware_index = None;
        self.watchpoints[index].is_enabled = false;
        Ok(())
    }

    /// Creates a new breakpoint site at the specified address.
    /// If `enable_after_creation` is true, the breakpoint will be enabled immediately after creation.
    pub fn create_breakpoint<'a>(
        &'a mut self,
        address: VirtAddress,
        enable_after_creation: bool,
        is_hardware: bool,
    ) -> Result<&'a mut Breakpoint> {
        if self
            .breakpoints
            .iter()
            .any(|bp| bp.virtual_address == address)
        {
            return Err(anyhow!(
                "Breakpoint site already exists at address: {}",
                address
            ));
        }
        self.breakpoints
            .push(Breakpoint::new(address, false, is_hardware));
        if enable_after_creation {
            let index = self.breakpoints.len() - 1;
            self.enable_breakpoint_at_index(index)
                .context("Failed to enable breakpoint after creation")?;
        }
        Ok(self.breakpoints.last_mut().unwrap())
    }

    fn find_free_stop_point_register(control: u64) -> Result<u8> {
        // Check the control register to find a free debug register.
        /*
        Bit 0 Local DR0 breakpoint enabled
        Bit 1 Global DR0 breakpoint enabled
        --------------------------------
        Bit 2 Local DR1 breakpoint enabled
        Bit 3 Global DR1 breakpoint enabled
        --------------------------------
        Bit 4 Local DR2 breakpoint enabled
        Bit 5 Global DR2 breakpoint enabled
        --------------------------------
        Bit 6 Local DR3 breakpoint enabled
        Bit 7 Global DR3 breakpoint enabled
        --------------------------------
        ...
        ...
        ...
         */
        for i in 0..4u8 {
            if (control & (0b11 << (i * 2))) == 0 {
                return Ok(i);
            }
        }
        Err(anyhow!("No free debug registers available"))
    }

    fn encode_mode_flag(mode: StopPointMode) -> u64 {
        match mode {
            StopPointMode::Write => 0b01,     // Write access
            StopPointMode::ReadWrite => 0b11, // Read and write access
            StopPointMode::Execute => 0b00,   // Execute access
        }
    }

    fn encode_size_flag(size: usize) -> u64 {
        match size {
            1 => 0b00, // 1 byte
            2 => 0b01, // 2 bytes
            4 => 0b11, // 4 bytes
            8 => 0b10, // 8 bytes
            _ => panic!("Invalid size for hardware stop point: {}", size),
        }
    }

    /// Sets a hardware stop point at the specified address with the given size and mode.
    /// This function finds a free debug register, writes the address to it, and encodes
    /// the stop point mode and size into the control register.
    /// Returns the index of the debug register used for the stop point.
    pub fn set_hardware_breakpoint(
        &mut self,
        address: VirtAddress,
        size: usize,
        mode: StopPointMode,
    ) -> Result<u8> {
        assert!(
            self.is_attached,
            "Process must be attached to set hardware stop point"
        );
        /*
               https://wiki.osdev.org/CPU_Registers_x86-64#DR7
               Bit	Description
               0	Local DR0 Breakpoint
               1	Global DR0 Breakpoint
               2	Local DR1 Breakpoint
               3	Global DR1 Breakpoint
               4	Local DR2 Breakpoint
               5	Global DR2 Breakpoint
               6	Local DR3 Breakpoint
               7	Global DR3 Breakpoint
               16-17	Conditions for DR0
               18-19	Size of DR0 Breakpoint
               20-21	Conditions for DR1
               22-23	Size of DR1 Breakpoint
               24-25	Conditions for DR2
               26-27	Size of DR2 Breakpoint
               28-29	Conditions for DR3
               30-31	Size of DR3 Breakpoint
        */
        // Step 1: Find a free space among the DR registers for the new stop point by locating one that isn’t yet enabled.
        let control: u64 = match self
            .registers
            .get_register_value(register_info::RegisterId::dr(7))?
        {
            RegisterValue::U64(value) => value,
            _ => panic!("Unexpected register value type for DR7"),
        };
        let free_register_index = Self::find_free_stop_point_register(control)
            .context("Failed to find free debug register")?;
        assert!(
            free_register_index < 4,
            "Free register index out of bounds: {}",
            free_register_index
        );

        // Step 2: Write the desired address to the correct DR register.
        let debug_register_id = register_info::RegisterId::dr(free_register_index as u32);
        self.write_register_value(debug_register_id, RegisterValue::U64(address.get() as u64))
            .context("Failed to write debug register value")?;

        // Step 3: Encode the stop point mode and size into the form expected by the control register.
        let mode_flag = Self::encode_mode_flag(mode);
        let size_flag = Self::encode_size_flag(size);
        let enable_bit = 0b1u64 << (free_register_index * 2);
        let mode_bits = mode_flag << (free_register_index * 4 + 16);
        let size_bits = size_flag << (free_register_index * 4 + 18);
        let clear_mask = (0b11u64 << (free_register_index * 2)) | // Clear the bits for the free register
                         (0b1111u64 << (free_register_index * 4 + 16)); // Clear the mode and byte bits
        let masked = control & !clear_mask; // Clear the bits for the free register and mode bits
        let masked = masked | enable_bit | mode_bits | size_bits; // Set the bits for the free register and mode bits
        self.write_register_value(register_info::RegisterId::dr(7), RegisterValue::U64(masked))
            .context("Failed to write control register value")?;
        // Step 4: Return the index of the debug register used for the stop point.
        Ok(free_register_index)
    }

    /// Clears the hardware stop point at the specified index.
    /// This function clears the bits for the specified debug register in the control register.
    /// The index should be in the range of 0 to 3, corresponding to DR0 to DR3.
    /// Returns a Result indicating success or failure.
    pub fn clear_hardware_breakpoint(&mut self, index: u8) -> Result<()> {
        assert!(
            self.is_attached,
            "Process must be attached to clear hardware stop point"
        );
        assert!(
            index < 4,
            "Index out of bounds for hardware stop point: {}",
            index
        );
        // Clear the bits for the specified debug register in the control register.
        let control: u64 = match self
            .registers
            .get_register_value(register_info::RegisterId::dr(7))?
        {
            RegisterValue::U64(value) => value,
            _ => panic!("Unexpected register value type for DR7"),
        };
        let clear_mask = 0b11u64 << (index * 2) |// Clear the bits for the specified debug register 
                            0b1111u64 << (index * 4 + 16); // Clear the mode and byte size bits
        let masked = control & !clear_mask; // Clear the bits for the specified debug register and mode bits
        self.write_register_value(register_info::RegisterId::dr(7), RegisterValue::U64(masked))
            .context("Failed to clear hardware stop point")?;
        Ok(())
    }

    pub fn remove_breakpoint_by_id(&mut self, id: StopPointId) -> Result<()> {
        let position = self
            .breakpoints
            .iter()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;
        self.disable_breakpoint_by_id(id)
            .context("Failed to disable breakpoint site before removing")?;
        self.breakpoints.remove(position);
        Ok(())
    }

    pub fn remove_watchpoint_by_id(&mut self, id: StopPointId) -> Result<()> {
        let position = self
            .watchpoints
            .iter()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;
        self.disable_watchpoint_by_id(id)
            .context("Failed to disable breakpoint site before removing")?;
        self.watchpoints.remove(position);
        Ok(())
    }

    fn enable_breakpoint_at_index(&mut self, index: usize) -> Result<()> {
        if self.breakpoints[index].is_enabled {
            return Ok(()); // Breakpoint is already enabled, no action needed
        }
        let hardware_index = {
            if self.breakpoints[index].is_hardware {
                Some(self.set_hardware_breakpoint(
                    self.breakpoints[index].virtual_address(),
                    1,
                    StopPointMode::Execute,
                )?)
            } else {
                None
            }
        };
        let breakpoint = &mut self.breakpoints[index];
        if let Some(hardware_index) = hardware_index {
            breakpoint.hardware_index = Some(hardware_index);
            breakpoint.is_enabled = true;
            return Ok(()); // Hardware breakpoint set, no need to write to memory
        }
        // This is a software breakpoint, so we need to write the breakpoint/int3 instruction to the process memory.
        // Read a word from the process memory at the breakpoint address
        let data = nix::sys::ptrace::read(self.pid, breakpoint.virtual_address.address as *mut _)
            .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))
            .expect("Failed to read memory at breakpoint address");
        breakpoint.saved_data = Some((data as u64 & 0xFFu64) as u8);
        const INT3: u8 = 0xCC; // Breakpoint instruction
        let data_with_int3: u64 = (data as u64 & !0xFFu64) | INT3 as u64;
        // Write the breakpoint instruction to the process memory
        nix::sys::ptrace::write(
            self.pid,
            breakpoint.virtual_address.address as *mut _,
            data_with_int3 as c_long,
        )
        .context("Failed to write memory at breakpoint address")?;
        breakpoint.is_enabled = true;
        Ok(())
    }

    fn disable_breakpoint_at_index(&mut self, index: usize) -> Result<()> {
        if !self.breakpoints[index].is_enabled {
            return Ok(()); // Breakpoint is already disabled, no action needed
        }
        if let Some(hardware_index) = self.breakpoints[index].hardware_index {
            // If this is a hardware breakpoint, we need to clear it.
            self.clear_hardware_breakpoint(hardware_index)
                .context("Failed to clear hardware stop point")?;
            self.breakpoints[index].hardware_index = None;
            self.breakpoints[index].is_enabled = false;
            return Ok(()); // Hardware breakpoint cleared, no need to write to memory
        }
        let breakpoint = &mut self.breakpoints[index];
        let data = nix::sys::ptrace::read(self.pid, breakpoint.virtual_address.address as *mut _)
            .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))?;
        // Read the saved data from the breakpoint site
        let restored_word = (data as u64 & !0xFFu64)
            | breakpoint.saved_data.expect("saved_data should be present") as u64;
        // Write the original instruction back to the process memory
        nix::sys::ptrace::write(
            self.pid,
            breakpoint.virtual_address.address as *mut _,
            restored_word as c_long,
        )
        .context("Failed to write memory at breakpoint address")?;
        breakpoint.is_enabled = false;
        Ok(())
    }

    pub fn enable_breakpoint_by_id(&mut self, id: StopPointId) -> Result<()> {
        let index = self
            .breakpoints
            .iter_mut()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;

        self.enable_breakpoint_at_index(index)?;
        Ok(())
    }

    pub fn disable_breakpoint_by_id(&mut self, id: StopPointId) -> Result<()> {
        let index = self
            .breakpoints
            .iter_mut()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;
        self.disable_breakpoint_at_index(index)?;
        Ok(())
    }

    pub fn enable_watchpoint_by_id(&mut self, id: StopPointId) -> Result<()> {
        let index = self
            .watchpoints
            .iter_mut()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Watchpoint site with ID {} not found", id))?;
        self.enable_watchpoint_at_index(index)?;
        Ok(())
    }

    pub fn disable_watchpoint_by_id(&mut self, id: StopPointId) -> Result<()> {
        let index = self
            .watchpoints
            .iter_mut()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Watchpoint site with ID {} not found", id))?;
        self.disable_watchpoint_at_index(index)?;
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.is_attached {
            if self.state == ProcessHandleState::Running {
                nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGSTOP)
                    .expect("Failed to stop process");
                self.wait_on_signal(None)
                    .expect("Failed to wait for process");
            }
            if self.state == ProcessHandleState::Stopped
                || self.state == ProcessHandleState::Running
            {
                nix::sys::ptrace::detach(self.pid, None).expect("Failed to detach from process");
                nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGCONT)
                    .expect("Failed to continue process after detaching");
            }
        }
        if self.terminate_on_end {
            let _ = nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGKILL);
            let _ = self.wait_on_signal(None);
        }
    }
}

/// Sets up the child process for debugging. This function is called in the child process after a fork.
/// It enables tracing for the child process and loads the executable into it. It also passes the arguments to the executable.
fn setup_child_process(
    executable_path: &PathBuf,
    args: Option<String>,
    attach_for_debugging: bool,
) -> Result<()> {
    // Change the process group of the inferior process to its own group.
    // This is necessary for the process to be able to receive signals.
    // Forked processes run in the same process group as their parent, so when sdb gets a SIGINT, the inferior gets a SIGINT.
    unsafe {
        if libc::setpgid(0, 0) == -1 {
            let err = anyhow!(
                "Failed to set process group ID in child process: {}",
                nix::errno::Errno::last().desc()
            );
            Errno::clear();
            return Err(err);
        }
    };
    // Disable address space layout randomization (ASLR) for the child process
    unsafe {
        let status = personality(libc::ADDR_NO_RANDOMIZE as u64);
        if status == -1 {
            let err = anyhow!(
                "Failed to disable ASLR in child process: {}",
                nix::errno::Errno::last().desc()
            );
            Errno::clear();
            return Err(err);
        }
    };

    let executable_path_cstring = CString::new(executable_path.to_str().unwrap())?;
    let mut args_cstrings: Vec<CString> = vec![executable_path_cstring.clone()];
    if let Some(args) = args {
        args_cstrings.extend(
            args.split_ascii_whitespace()
                .map(|arg| CString::new(arg).unwrap()) // Convert each argument to CString
                .collect::<Vec<_>>(),
        );
    }
    if attach_for_debugging {
        traceme().context("Failed to enable tracing in child process")?;
    }
    execvp(&executable_path_cstring, &args_cstrings).context("Failed to launch executable")?;
    Ok(())
}

pub fn process_with_pid_exists(pid: Pid) -> bool {
    match nix::sys::signal::kill(pid, None) {
        Ok(_) => true,                          // Process exists
        Err(nix::errno::Errno::ESRCH) => false, // No such process(https://man7.org/linux/man-pages/man3/errno.3.html)
        Err(e) => panic!("Failed to check if process exists: {}", e),
    }
}

pub fn get_process_state(pid: Pid) -> Result<ProcessState> {
    let proc_path = format!("/proc/{}/stat", pid);
    let contents = std::fs::read_to_string(proc_path).context("Failed to read /proc file")?;
    let last_parenthesis = contents
        .rfind(')')
        .ok_or_else(|| anyhow!("Failed to find last parenthesis in /proc file"))?;
    let index_of_state_char = last_parenthesis + 2; // The state character is right after the last parenthesis
    let state_char = contents
        .chars()
        .nth(index_of_state_char)
        .ok_or_else(|| anyhow!("Failed to find state character in /proc file"))?;
    Ok(ProcessState::from(state_char))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtAddress {
    address: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopPointMode {
    ReadWrite,
    Write,
    Execute,
}

impl VirtAddress {
    pub fn new(address: usize) -> Self {
        VirtAddress { address }
    }

    pub fn get(self) -> usize {
        self.address
    }

    /// Returns the next page boundary address after this address.
    /// Example 4095 -> 4096
    /// Example 4096 -> 8192
    /// Example 8192 -> 12288
    /// Example 0 -> 4096
    pub fn next_page_boundary(&self) -> Self {
        const PAGE_SIZE: usize = 0x1000; // Assume 4 KiB page size
        VirtAddress {
            address: (self.address + PAGE_SIZE) & !0xFFF,
        }
    }
}

impl std::ops::Add<VirtAddress> for VirtAddress {
    type Output = Self;

    fn add(self, rhs: VirtAddress) -> Self::Output {
        VirtAddress::new(self.address + rhs.address)
    }
}

impl std::ops::Add<usize> for VirtAddress {
    type Output = VirtAddress;

    fn add(self, rhs: usize) -> Self::Output {
        VirtAddress::new(self.address + rhs)
    }
}

impl std::ops::Sub<VirtAddress> for VirtAddress {
    type Output = Self;

    fn sub(self, rhs: VirtAddress) -> Self::Output {
        VirtAddress::new(self.address - rhs.address)
    }
}

impl PartialOrd for VirtAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl Display for VirtAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.address)
    }
}

impl From<usize> for VirtAddress {
    fn from(address: usize) -> Self {
        VirtAddress::new(address)
    }
}

impl Into<usize> for VirtAddress {
    fn into(self) -> usize {
        self.address
    }
}

pub struct Registers {
    data: user,
}

impl Registers {
    fn new() -> Self {
        Registers {
            // Safety: This is safe because we are initializing the `user` struct to zero.
            // The `user` struct is used to hold the registers and is expected to be zeroed out before use.
            data: { unsafe { std::mem::zeroed::<libc::user>() } },
        }
    }

    fn set_register_value(
        &mut self,
        register_info: &'static RegisterInfo,
        value: RegisterValue,
    ) -> Result<()> {
        let payload_size = value.get_payload_size_in_bytes();
        if payload_size <= register_info.size {
            let value_widened = value.widen_to_fixed_buffer(&register_info);
            let structure_bytes = register_info::as_mutable_bytes_of_struct::<user>(&mut self.data);
            value_widened[0..register_info.size]
                .iter()
                .enumerate()
                .for_each(|(i, &byte)| {
                    structure_bytes[register_info.offset as usize + i] = byte;
                });
        } else {
            panic!(
                "Register value size {} exceeds register info size {}",
                payload_size, register_info.size
            );
        }
        Ok(())
    }

    /// Load a register’s value from `self.data` and wrap it in the right enum variant.
    pub fn get_register_value(&self, id: register_info::RegisterId) -> Result<RegisterValue> {
        let info = register_info::get_register_info(id)
            .ok_or_else(|| anyhow!("unknown register {:?}", id))?;
        let off = info.offset as usize;

        // ↓ one-liner to avoid writing the same call 9×
        macro_rules! load {
            ($ty:ty) => {
                register_info::coerce_bytes_of_struct_to_type_at_offset::<user, $ty>(
                    &self.data, off,
                )
            };
        }

        use RegisterFormat::*;

        Ok(match (info.reg_format, info.size) {
            // ───── unsigned integers ─────
            (UnsignedInt, 1) => RegisterValue::U8(load!(u8)?),
            (UnsignedInt, 2) => RegisterValue::U16(load!(u16)?),
            (UnsignedInt, 4) => RegisterValue::U32(load!(u32)?),
            (UnsignedInt, 8) => RegisterValue::U64(load!(u64)?),

            // ───── floating-point ─────
            (DoubleFloat, 4) => RegisterValue::F32(load!(f32)?),
            (DoubleFloat, 8) => RegisterValue::F64(load!(f64)?),
            (LongDouble, 16) => RegisterValue::LongDouble(load!([u8; 16])?),

            // ───── vectors ─────
            (Vector, 8) => RegisterValue::Byte64(load!([u8; 8])?),
            (Vector, 16) => RegisterValue::Byte128(load!([u8; 16])?),

            // ───── anything else ─────
            (fmt, sz) => anyhow::bail!("unsupported register: {:?} ({} bytes)", fmt, sz),
        })
    }
}

pub type StopPointId = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareStopPointId {
    HardwareStopPointId(StopPointId),
    WatchpointId(StopPointId),
}

#[derive(Debug)]
pub struct Watchpoint {
    id: StopPointId,
    is_enabled: bool,
    virtual_address: VirtAddress,
    mode: StopPointMode,
    size: u8,
    hardware_index: Option<u8>, // Only used for hardware breakpoints
    data: Option<u64>,
    previous_data: Option<u64>,
}

impl Watchpoint {
    fn new(virtual_address: VirtAddress, mode: StopPointMode, size: u8) -> Result<Self> {
        let address_usize = virtual_address.get() as usize;
        if address_usize & (size as usize - 1) != 0 {
            return Err(anyhow!(
                "Watchpoint address must be aligned to the size: address = 0x{:x}, size = {}",
                address_usize,
                size
            ));
        }
        Ok(Watchpoint {
            id: get_next_stoppoint_id(),
            is_enabled: false,
            virtual_address,
            mode,
            size,
            hardware_index: None,
            data: None,
            previous_data: None,
        })
    }

    pub fn mode(&self) -> StopPointMode {
        self.mode
    }

    pub fn virtual_address(&self) -> VirtAddress {
        self.virtual_address
    }

    pub fn id(&self) -> StopPointId {
        self.id
    }

    pub fn get_data(&self) -> Option<u64> {
        self.data
    }

    pub fn get_previous_data(&self) -> Option<u64> {
        self.previous_data
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }
}

#[derive(Debug)]
pub struct Breakpoint {
    id: StopPointId,
    is_enabled: bool,
    virtual_address: VirtAddress,
    saved_data: Option<u8>,
    _is_internal: bool,
    is_hardware: bool,
    hardware_index: Option<u8>, // Only used for hardware breakpoints
}

fn get_next_stoppoint_id() -> StopPointId {
    static NEXT_ID: std::sync::Mutex<StopPointId> = std::sync::Mutex::new(0);
    let mut id = NEXT_ID.lock().unwrap();
    let next_id = *id;
    *id += 1;
    next_id
}

impl Breakpoint {
    fn new(virtual_address: VirtAddress, is_internal: bool, is_hardware: bool) -> Self {
        Breakpoint {
            id: get_next_stoppoint_id(),
            is_enabled: false,
            virtual_address,
            saved_data: None,
            _is_internal: is_internal,
            is_hardware,
            hardware_index: None,
        }
    }

    pub fn virtual_address(&self) -> VirtAddress {
        self.virtual_address
    }

    pub fn id(&self) -> StopPointId {
        self.id
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_next_id() {
        assert_eq!(get_next_stoppoint_id(), 0);
        assert_eq!(get_next_stoppoint_id(), 1);
        assert_eq!(get_next_stoppoint_id(), 2);
        assert_eq!(get_next_stoppoint_id(), 3);
        assert_eq!(get_next_stoppoint_id(), 4);
        assert_eq!(get_next_stoppoint_id(), 5);
    }

    #[test]
    fn test_virt_address() {
        let va = VirtAddress::new(0x1234);
        assert_eq!(va.next_page_boundary().address, 0x2000);
        assert_eq!(va.next_page_boundary().next_page_boundary().address, 0x3000);
        assert_eq!(
            va.next_page_boundary()
                .next_page_boundary()
                .next_page_boundary()
                .address,
            0x4000
        );
        let va = VirtAddress::new(4095);
        assert_eq!(va.next_page_boundary().address, 4096);
        assert_eq!(va.next_page_boundary().next_page_boundary().address, 8192);
    }
}
