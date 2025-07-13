/////////////////////////////////////////
use std::ffi::CString;
use std::fmt::Display;
use std::path::PathBuf;
/////////////////////////////////////////
use anyhow::{Context, Result, anyhow};
use core::panic;
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
    pub breakpoint_sites: Vec<BreakpointSite>,
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
            breakpoint_sites: Vec::new(),
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
                    breakpoint_sites: Vec::new(),
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
            let instruction_begin = self.get_pc()? - VirtAddress::new(1usize);
            if self
                .breakpoint_sites
                .iter()
                .find(|bp| bp.get_virtual_address() == instruction_begin && bp.is_enabled())
                .is_some()
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
        // If the breakpoint at PC is enabled, we need to disable it before resuming.
        if let Some(index) = self
            .breakpoint_sites
            .iter()
            .position(|bp| bp.get_virtual_address() == pc && bp.is_enabled())
        {
            // Disable the breakpoint at PC, step over the int3 instruction, and then re-enable it.
            // This is necessary to avoid hitting the breakpoint again immediately after resuming.
            let breakpoint_site = self
                .breakpoint_sites
                .get_mut(index)
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
            .iter()
            .position(|bp| bp.get_virtual_address() == program_counter)
        {
            let breakpoint = &mut self.breakpoint_sites[breakpoint_site_index];
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
            let breakpoint = &mut self.breakpoint_sites[breakpoint_site_index];
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
        for breakpoint in self.breakpoint_sites.iter() {
            if breakpoint.is_enabled() {
                let break_point_address = breakpoint.get_virtual_address();
                if break_point_address >= start && break_point_address < start + num_bytes {
                    let offset = break_point_address - start;
                    bytes[offset.get()] = breakpoint
                        .get_data()
                        .expect("Breakpoint data should be present");
                }
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

    pub fn create_breakpoint_site<'a>(
        &'a mut self,
        address: VirtAddress,
    ) -> Result<&'a mut BreakpointSite> {
        if self
            .breakpoint_sites
            .iter()
            .any(|bp| bp.get_virtual_address() == address)
        {
            return Err(anyhow!(
                "Breakpoint site already exists at address: {}",
                address
            ));
        }
        self.breakpoint_sites
            .push(BreakpointSite::new(address, self.pid));
        Ok(self.breakpoint_sites.last_mut().unwrap())
    }

    fn find_free_stop_point_register(control: u64) -> Result<u32> {
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
        for i in 0..4u32 {
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
    pub fn set_hardware_stoppoint(
        &mut self,
        address: VirtAddress,
        size: usize,
        mode: StopPointMode,
    ) -> Result<u32> {
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
    pub fn clear_hardware_stoppoint(&mut self, index: u32) -> Result<()> {
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

    pub fn remove_stop_point_by_id(&mut self, id: StopPointId) -> Result<()> {
        let position = self
            .breakpoint_sites
            .iter()
            .position(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;
        let breakpoint_site = &mut self.breakpoint_sites[position];
        if breakpoint_site.is_enabled() {
            breakpoint_site.disable()?;
        }
        self.breakpoint_sites.remove(position);
        Ok(())
    }

    pub fn enable_breakpoint_site(&mut self, id: StopPointId) -> Result<()> {
        let breakpoint = self
            .breakpoint_sites
            .iter_mut()
            .find(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;
        breakpoint.enable()?;
        Ok(())
    }

    pub fn disable_breakpoint_site(&mut self, id: StopPointId) -> Result<()> {
        let breakpoint = self
            .breakpoint_sites
            .iter_mut()
            .find(|site| site.id == id)
            .ok_or(anyhow!("Breakpoint site with ID {} not found", id))?;
        breakpoint.disable()?;
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

#[derive(Debug, Copy, Clone)]
pub struct BreakpointSite {
    id: StopPointId,
    is_enabled: bool,
    virtual_address: VirtAddress,
    saved_data: Option<u8>,
    pid: Pid,
}

impl BreakpointSite {
    fn get_next_id() -> StopPointId {
        static NEXT_ID: std::sync::Mutex<StopPointId> = std::sync::Mutex::new(0);
        let mut id = NEXT_ID.lock().unwrap();
        let next_id = *id;
        *id += 1;
        next_id
    }

    fn new(virtual_address: VirtAddress, pid: Pid) -> Self {
        BreakpointSite {
            id: BreakpointSite::get_next_id(),
            is_enabled: false,
            virtual_address,
            saved_data: None,
            pid,
        }
    }

    pub fn enable(&mut self) -> Result<()> {
        if self.is_enabled {
            return Ok(());
        }
        // Read a word from the process memory at the breakpoint address
        let data = nix::sys::ptrace::read(self.pid, self.virtual_address.address as *mut _)
            .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))?;
        self.saved_data = Some((data as u64 & 0xFFu64) as u8);
        const INT3: u8 = 0xCC; // Breakpoint instruction
        let data_with_int3: u64 = (data as u64 & !0xFFu64) | INT3 as u64;
        // Write the breakpoint instruction to the process memory
        nix::sys::ptrace::write(
            self.pid,
            self.virtual_address.address as *mut _,
            data_with_int3 as c_long,
        )
        .context("Failed to write memory")?;
        self.is_enabled = true;
        Ok(())
    }

    pub fn disable(&mut self) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }
        let data = nix::sys::ptrace::read(self.pid, self.virtual_address.address as *mut _)
            .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))?;
        let restored_word = (data as u64 & !0xFFu64)
            | self.saved_data.expect("saved_data should be present") as u64;
        // Write the original instruction back to the process memory
        nix::sys::ptrace::write(
            self.pid,
            self.virtual_address.address as *mut _,
            restored_word as c_long,
        )
        .context("Disabling breakpoint failed. Failed to write memory")?;
        self.is_enabled = false;
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn get_virtual_address(&self) -> VirtAddress {
        self.virtual_address
    }

    pub fn in_range(&self, low: VirtAddress, high: VirtAddress) -> bool {
        self.virtual_address >= low && self.virtual_address < high
    }

    pub fn is_at_address(&self, address: VirtAddress) -> bool {
        self.virtual_address == address
    }

    pub fn get_id(&self) -> StopPointId {
        self.id
    }

    pub fn get_data(&self) -> Option<u8> {
        self.saved_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_next_id() {
        assert_eq!(BreakpointSite::get_next_id(), 0);
        assert_eq!(BreakpointSite::get_next_id(), 1);
        assert_eq!(BreakpointSite::get_next_id(), 2);
        assert_eq!(BreakpointSite::get_next_id(), 3);
        assert_eq!(BreakpointSite::get_next_id(), 4);
        assert_eq!(BreakpointSite::get_next_id(), 5);
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
