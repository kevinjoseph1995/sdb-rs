/////////////////////////////////
/// External
use nix::sys::ptrace::traceme;
use nix::unistd::execvp;
use std::ffi::CString;
use std::path::PathBuf;
/////////////////////////////////

// Export the necessary modules and types as is
pub use nix::sys::ptrace::attach;
pub use nix::sys::wait::waitpid;
pub use nix::unistd::{ForkResult, fork};
pub type Pid = nix::unistd::Pid;

/// Launches a new inferior process for debugging.
/// This function forks the current process and sets up the child process for debugging.
/// It enables tracing for the child process and loads the executable into it.
pub fn launch_and_setup_inferior_process(
    executable_path: &PathBuf,
    args: &Option<String>,
) -> Result<Pid, Box<dyn std::error::Error>> {
    println!("launch_and_setup_inferior_process: {:?}", executable_path);
    // Fork the current process
    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => {
            // In the parent process, return the child's PID
            Ok(child)
        }
        ForkResult::Child => {
            // In the child process, set up the child process
            let result = setup_child_process(executable_path, args);
            if let Err(e) = result {
                eprintln!("Failed to set up child process: {}", e);
                std::process::exit(1); // Exit the child process with an error
            }
            unreachable!(); // execvp replaces the child process, so this line should never be reached
        }
    }
}

/// Sets up the child process for debugging. This function is called in the child process after a fork.
/// It enables tracing for the child process and loads the executable into it. It also passes the arguments to the executable.
fn setup_child_process(
    executable_path: &PathBuf,
    args: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Enable tracing for the child process
    traceme().map_err(|e| {
        eprintln!("Failed to enable tracing for child process: {}", e);
        e
    })?;
    // Load the executable into the child process
    // and pass the arguments to it.
    let executable_path_cstring = CString::new(executable_path.to_str().unwrap())?;
    let mut args_cstrings: Vec<CString> = vec![executable_path_cstring.clone()]; // First argument is the executable path
    // If args is Some, split it by spaces and convert to CString
    // and add to args_cstrings.
    // If args is None, just use the executable path.
    if let Some(args) = args {
        args_cstrings.extend(
            args.split(' ')
                .map(|arg| CString::new(arg).unwrap()) // Convert each argument to CString
                .collect::<Vec<_>>(),
        );
    }
    execvp(&executable_path_cstring, &args_cstrings)?;
    Ok(())
}

pub fn attach_to_process(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    // Attach to the process with the given PID
    attach(pid)?;
    // Wait for the process to stop
    match waitpid(pid, None)? {
        nix::sys::wait::WaitStatus::Stopped(_, _) => {
            println!("Attached to process: {}", pid);
        }
        _ => {
            return Err("Failed to attach to process".into());
        }
    }
    Ok(())
}

pub fn resume_process(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = nix::sys::ptrace::cont(pid, None) {
        eprintln!("Failed to resume process: {}", e);
        return Err(e.into());
    }
    Ok(())
}
