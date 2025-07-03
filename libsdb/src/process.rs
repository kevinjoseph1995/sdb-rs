/////////////////////////////////////////
use std::ffi::CString;
use std::path::PathBuf;
/////////////////////////////////////////
use anyhow::{Context, Result, anyhow};
use core::panic;
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
/////////////////////////////////////////
use crate::breakpoint::BreakpointSite;
use crate::breakpoint::StopPoint;
use crate::breakpoint::StopPointCollection;
use crate::breakpoint::VirtAddress;
use crate::pipe_channel;
use crate::register_info;
use crate::register_info::RegisterFormat;
use crate::register_info::RegisterInfo;
use crate::register_info::RegisterType;
use crate::register_info::RegisterValue;

type Pid = nix::unistd::Pid;

#[derive(PartialEq)]
enum ProcessHandleState {
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

pub struct Process {
    pub pid: Pid,
    terminate_on_end: bool,
    state: ProcessHandleState,
    read_port: Option<pipe_channel::ReadPort>,
    is_attached: bool,
    registers: Registers,
    pub breakpoint_sites: StopPointCollection<BreakpointSite>,
}

impl Process {
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
            breakpoint_sites: StopPointCollection::<BreakpointSite>::new(),
        };
        let _stop_reason = child_process_handle.wait_on_signal(None)?;
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
                    breakpoint_sites: StopPointCollection::<BreakpointSite>::new(),
                };
                println!("Launching process with PID: {}", child_process_handle.pid);
                if debug_process_being_launched {
                    // If we are debugging the process being launched, we need to wait for it to stop.
                    // traceme() is called in the child process, so we need to wait for it to stop.
                    match child_process_handle.wait_on_signal(None)? {
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

    pub fn get_registers(&self) -> &Registers {
        return &self.registers;
    }

    /// Waits for the process to stop or exit. This function blocks until the process undergoes a state change.
    pub fn wait_on_signal(&mut self, options: Option<WaitPidFlag>) -> Result<WaitStatus> {
        let waitstatus: WaitStatus =
            waitpid(self.pid, options).context("Failed to wait for process")?;
        match &waitstatus {
            WaitStatus::Exited(_, _) => {
                self.state = ProcessHandleState::Exited;
            }
            WaitStatus::Signaled(_pid, _signal, _) => {
                self.state = ProcessHandleState::Terminated;
            }
            WaitStatus::Stopped(_pid, _signal) => {
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
        if let WaitStatus::Stopped(_, Signal::SIGTRAP) = waitstatus {
            // When the process stops due to a SIGTRAP, it is likely due to a breakpoint or single-step.
            let instruction_begin = self.get_pc()?.subtract(1);
            if self
                .breakpoint_sites
                .is_enabled_at_address(instruction_begin)
            {
                // If the breakpoint is enabled at the instruction address, we need to set the PC to the instruction address.
                self.set_pc(instruction_begin)?;
            }
        }
        Ok(waitstatus)
    }

    /// Resumes the execution of the process being debugged.
    pub fn resume_process(&mut self) -> Result<()> {
        let pc = self
            .get_pc()
            .context("Failed to get program counter (PC) register")?;
        if self.breakpoint_sites.is_enabled_at_address(pc) {
            let breakpoint_site = self
                .breakpoint_sites
                .get_stop_point_by_address_mut(pc)
                .ok_or_else(|| anyhow!("Breakpoint site not found at address: {}", pc))?;
            breakpoint_site.disable()?;
            ptrace::step(self.pid, None).context("Failed to step process")?; // Step over the int3 instruction.
            waitpid(self.pid, None).context("Failed to wait for process after stepping")?;
            breakpoint_site.enable()?;
        }

        if let Err(e) = nix::sys::ptrace::cont(self.pid, None) {
            eprintln!("Failed to resume process: {}", e);
            return Err(e.into());
        }
        self.state = ProcessHandleState::Running;
        Ok(())
    }

    pub fn single_step(&mut self) -> Result<WaitStatus> {
        assert!(self.is_attached, "Process must be attached to single step");

        let mut breakpoint_to_reenable: Option<usize> = None;
        let program_counter = self.get_pc()?;
        if let Some(breakpoint_site_index) = self
            .breakpoint_sites
            .get_stop_point_index_by_address(program_counter)
        {
            let breakpoint = &mut self.breakpoint_sites.stop_points[breakpoint_site_index];
            if breakpoint.is_enabled() {
                // If the breakpoint is enabled at the instruction address, we need to disable it before single stepping.
                breakpoint.disable()?;
                breakpoint_to_reenable = Some(breakpoint_site_index);
            }
        }
        nix::sys::ptrace::step(self.pid, None).context("Failed to step process")?;
        let reason = self.wait_on_signal(None)?;
        // Re-enable the breakpoint if it was enabled before the single step.
        if let Some(breakpoint_site_index) = breakpoint_to_reenable {
            let breakpoint = &mut self.breakpoint_sites.stop_points[breakpoint_site_index];
            breakpoint.enable()?;
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
                    let read_memory = self.read_memory(start.add(written), 8)?;
                    chunk.copy_from_slice(&read_memory[0..8]); // Copy the existing memory to the chunk
                    chunk[0..remaining_bytes.len()].copy_from_slice(remaining_bytes); // Copy the new data to the first part
                    chunk
                }
            };
            ptrace::write(
                self.pid,
                start.add(written).get() as *mut std::ffi::c_void,
                i64::from_le_bytes(eight_byte_chunk),
            )
            .context("Failed to write memory")?;

            written += 8;
        }

        Ok(())
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
                let chunk_size =
                    std::cmp::min(num_bytes, next_page_boundary.subtract(start.get()).get());
                remote_iovs.push(RemoteIoVec {
                    base: start.get(),
                    len: chunk_size,
                });
                start = start.add(chunk_size);
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

    pub fn create_breakpoint_site<'a>(
        &'a mut self,
        address: VirtAddress,
    ) -> Result<&'a mut BreakpointSite> {
        if self.breakpoint_sites.contains_address(address) {
            return Err(anyhow!(
                "Breakpoint site already exists at address: {}",
                address
            ));
        }
        self.breakpoint_sites
            .push_and_return_mut_ref(BreakpointSite::new(address, self.pid))
            .ok_or_else(|| anyhow!("Failed to create breakpoint site at address: {}", address))
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

#[cfg(test)]
mod tests {

    use crate::{
        breakpoint::StopPoint,
        pipe_channel::{ChannelPort, create_pipe_channel},
    };

    use super::*;
    use extended::Extended;
    use procfs::process::MMPermissions;
    use test_binary::build_test_binary;

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
        let mut target_process = Process::launch(&PathBuf::from("yes"), None, true, None)
            .expect("Process failed to launch");
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
        let (read_port, write_port) =
            create_pipe_channel(true).expect("Failed to create pipe channel");
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
        let mut target_process = Process::launch(&PathBuf::from("yes"), None, true, None)
            .expect("Process failed to launch");
        {
            assert_eq!(
                target_process
                    .create_breakpoint_site(VirtAddress::new(0x1000))
                    .expect("Failed to create breakpoint site at 0x1000")
                    .get_virtual_address(),
                VirtAddress::new(0x1000)
            );
        }
        assert_eq!(
            target_process
                .create_breakpoint_site(VirtAddress::new(0x2000))
                .expect("Failed to create breakpoint site at 0x2000")
                .get_id()
                + 1,
            target_process
                .create_breakpoint_site(VirtAddress::new(0x3000))
                .expect("Failed to create breakpoint site at 0x3000")
                .get_id()
        );
        assert!(
            target_process
                .create_breakpoint_site(VirtAddress::new(0x1000))
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
        let entry_point_offset = file
            .ehdr
            .e_entry
            .checked_sub(section_load_bias)
            .ok_or_else(|| anyhow!("Failed to compute entry point address"))?
            as usize;

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

        let load_address = get_load_address(target_process.pid, offset as u64)
            .expect("Failed to get load address");
        let break_point_site = target_process
            .create_breakpoint_site(load_address)
            .expect("Failed to create breakpoint site at load address");
        break_point_site
            .enable()
            .expect("Failed to enable breakpoint site");
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
    fn test_memory_operations() {
        let test_binary_path = PathBuf::from(
            build_test_binary("memory_test", &PathBuf::from_iter(["..", "tools"]))
                .expect("Failed to build test binary"),
        );
        let (read_port, write_port) =
            create_pipe_channel(true).expect("Failed to create pipe channel");
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
}
