use anyhow::{Context, Result};
use nix::sys::ptrace::attach;
use nix::sys::ptrace::traceme;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
use nix::sys::wait::waitpid;
use nix::unistd::ForkResult;
use nix::unistd::execvp;
use nix::unistd::fork;
use std::ffi::CString;
use std::path::PathBuf;

use crate::pipe_channel;

type Pid = nix::unistd::Pid;

#[derive(PartialEq)]
enum ProcessState {
    Running,
    Stopped,
    Exited,
    Terminated,
}
#[derive(PartialEq, Debug)]
enum StopReason {
    Exited(i32 /*Exit stautus */),
    Stopped(Signal),
    Terminated(Signal),
}

pub struct Process {
    pub pid: Pid,
    terminate_on_end: bool,
    state: ProcessState,
    read_port: Option<pipe_channel::ReadPort>,
}

/// Sets up the child process for debugging. This function is called in the child process after a fork.
/// It enables tracing for the child process and loads the executable into it. It also passes the arguments to the executable.
fn setup_child_process(
    executable_path: &PathBuf,
    args: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let executable_path_cstring = CString::new(executable_path.to_str().unwrap())?;
    let mut args_cstrings: Vec<CString> = vec![executable_path_cstring.clone()];
    if let Some(args) = args {
        args_cstrings.extend(
            args.split_ascii_whitespace()
                .map(|arg| CString::new(arg).unwrap()) // Convert each argument to CString
                .collect::<Vec<_>>(),
        );
    }
    traceme().context("Failed to enable tracing in child process")?;
    execvp(&executable_path_cstring, &args_cstrings).context("Failed to launch executable")?;
    Ok(())
}

impl Process {
    /// Attaches to an existing process for debugging.
    pub fn attach(pid: Pid) -> Result<Self> {
        attach(pid).context("Failed to attach to process")?; // The tracee is sent a SIGSTOP, but will not necessarily have stopped by the completion of this call.
        let mut child_process_handle = Process {
            pid,
            terminate_on_end: false,
            state: ProcessState::Stopped,
            read_port: None,
        };
        let stop_reason = child_process_handle.wait_on_signal(None)?;
        assert_eq!(stop_reason, StopReason::Stopped(Signal::SIGSTOP));
        Ok(child_process_handle)
    }

    /// Launches a new inferior process for debugging.
    /// This function forks the current process and sets up the child process for debugging.
    /// It enables tracing for the child process and loads the executable into it.
    pub fn launch(executable_path: &PathBuf, args: &Option<String>) -> Result<Self> {
        let (read_port, write_port) = pipe_channel::create_pipe_channel(true)?;
        match unsafe { fork() }? {
            ForkResult::Parent { child, .. } => {
                drop(write_port);
                let mut child_process_handle = Process {
                    pid: child,
                    terminate_on_end: true,
                    state: ProcessState::Stopped,
                    read_port: Some(read_port),
                };
                let stop_reason = child_process_handle.wait_on_signal(None)?;
                assert_eq!(stop_reason, StopReason::Stopped(Signal::SIGTRAP));
                Ok(child_process_handle)
            }
            ForkResult::Child => {
                drop(read_port);
                let result = setup_child_process(executable_path, args);
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

    /// Waits for the process to stop or exit. This function blocks until the process undergoes a state change.
    fn wait_on_signal(&mut self, options: Option<WaitPidFlag>) -> Result<StopReason> {
        let stop_reason =
            StopReason::from(waitpid(self.pid, options).context("Failed to wait for process")?);
        match &stop_reason {
            StopReason::Exited(_) => self.state = ProcessState::Exited,
            StopReason::Stopped(_) => self.state = ProcessState::Stopped,
            StopReason::Terminated(_) => self.state = ProcessState::Terminated,
        }
        Ok(stop_reason)
    }

    /// Resumes the execution of the process being debugged.
    pub fn resume_process(&mut self) -> Result<()> {
        if let Err(e) = nix::sys::ptrace::cont(self.pid, None) {
            eprintln!("Failed to resume process: {}", e);
            return Err(e.into());
        }
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn stop_process(&mut self) -> Result<()> {
        if self.state == ProcessState::Running {
            kill(self.pid, Signal::SIGSTOP).context("Failed to stop process")?;
            self.state = ProcessState::Stopped;
            self.wait_on_signal(None)
                .context("Failed to wait for process")?;
        }
        self.state = ProcessState::Stopped;
        Ok(())
    }

    pub fn print_child_output(&mut self) -> Result<()> {
        if let Some(read_port) = &self.read_port {
            let output = read_port.read()?;
            print!("{}", String::from_utf8_lossy(&output));
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.state == ProcessState::Running {
            nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGSTOP)
                .expect("Failed to stop process");
            self.wait_on_signal(None)
                .expect("Failed to wait for process");
        }
        nix::sys::ptrace::detach(self.pid, None).expect("Failed to detach from process");
        nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGCONT)
            .expect("Failed to continue process after detaching");
        if self.terminate_on_end {
            nix::sys::signal::kill(self.pid, nix::sys::signal::Signal::SIGKILL)
                .expect("Failed to kill process");
            self.wait_on_signal(None)
                .expect("Failed to wait for process to terminate");
        }
    }
}

impl From<WaitStatus> for StopReason {
    fn from(value: WaitStatus) -> Self {
        match value {
            WaitStatus::Stopped(_, signal) => StopReason::Stopped(signal),
            WaitStatus::Exited(_, exit_status) => StopReason::Exited(exit_status),
            WaitStatus::Signaled(_, signal, _) => StopReason::Terminated(signal),
            _ => panic!("Unexpected wait status: {:?}", value),
        }
    }
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::Exited(status) => write!(f, "Exited with status: {}", status),
            StopReason::Stopped(signal) => write!(f, "Stopped by signal: {:?}", signal),
            StopReason::Terminated(signal) => write!(f, "Terminated by signal: {:?}", signal),
        }
    }
}
