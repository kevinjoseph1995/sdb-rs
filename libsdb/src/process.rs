use anyhow::{Context, Result, anyhow};
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
enum ProcessHandleState {
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

pub struct Process {
    pub pid: Pid,
    terminate_on_end: bool,
    state: ProcessHandleState,
    read_port: Option<pipe_channel::ReadPort>,
    is_attached: bool,
}

/// Sets up the child process for debugging. This function is called in the child process after a fork.
/// It enables tracing for the child process and loads the executable into it. It also passes the arguments to the executable.
fn setup_child_process(
    executable_path: &PathBuf,
    args: Option<String>,
    attach_for_debugging: bool,
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
        };
        let stop_reason = child_process_handle.wait_on_signal(None)?;
        assert_eq!(stop_reason, StopReason::Stopped(Signal::SIGSTOP));
        Ok(child_process_handle)
    }

    /// Launches a new inferior process for debugging.
    /// This function forks the current process and sets up the child process for debugging.
    /// It enables tracing for the child process and loads the executable into it.
    pub fn launch(
        executable_path: &PathBuf,
        args: Option<String>,
        debug_process_being_launched: bool,
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
                };
                if debug_process_being_launched {
                    match child_process_handle.wait_on_signal(None)? {
                        StopReason::Exited(exit_code) => {
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
                        StopReason::Terminated(signal) => {
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
                        StopReason::Stopped(_signal) => {}
                    }
                }
                child_process_handle.read_port = Some(read_port);
                Ok(child_process_handle)
            }
            ForkResult::Child => {
                drop(read_port);
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

    /// Waits for the process to stop or exit. This function blocks until the process undergoes a state change.
    fn wait_on_signal(&mut self, options: Option<WaitPidFlag>) -> Result<StopReason> {
        let stop_reason =
            StopReason::from(waitpid(self.pid, options).context("Failed to wait for process")?);
        match &stop_reason {
            StopReason::Exited(_) => self.state = ProcessHandleState::Exited,
            StopReason::Stopped(_) => self.state = ProcessHandleState::Stopped,
            StopReason::Terminated(_) => self.state = ProcessHandleState::Terminated,
        }
        Ok(stop_reason)
    }

    /// Resumes the execution of the process being debugged.
    pub fn resume_process(&mut self) -> Result<()> {
        if let Err(e) = nix::sys::ptrace::cont(self.pid, None) {
            eprintln!("Failed to resume process: {}", e);
            return Err(e.into());
        }
        self.state = ProcessHandleState::Running;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_launching() {
        let executable_path = PathBuf::from("ls");
        let args = Some("-l".to_string());
        let process_handle = Process::launch(&executable_path, args, true);
        assert!(process_handle.is_ok());
    }
    #[test]
    fn test_process_launching_missing_executable() {
        let executable_path = PathBuf::from("executable_that_does_not_exist");
        let process_handle = Process::launch(&executable_path, None, true);
        assert!(process_handle.is_err(), "{}", process_handle.err().unwrap());
    }

    #[test]
    fn test_process_exists() {
        let pid: Pid = {
            let executable_path = PathBuf::from("yes");
            let process_handle = Process::launch(&executable_path, None, true);
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
            Process::launch(&PathBuf::from("yes"), None, true).expect("Process failed to launch");
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
        let target_process =
            Process::launch(&PathBuf::from("yes"), None, false).expect("Process failed to launch");
        assert!(
            get_process_state(target_process.pid).expect("Failed to get process state")
                == ProcessState::Running
        );

        let mut attached_handle = Process::attach(target_process.pid).expect("Failed to attach");
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
}
