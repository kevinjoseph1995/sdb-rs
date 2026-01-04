use std::str::FromStr;

use anyhow::Result;
use libsdb::Sysno;
use libsdb::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatchpointCategory {
    Syscalls(SyscallCommandCategory),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallCommandCategory {
    Clear,
    Specific,
    All,
}

impl CatchpointCategory {
    pub fn handle_command(&self, args: Vec<String>, process: &mut Process) -> Result<()> {
        match self {
            CatchpointCategory::Syscalls(syscall_command_category) => {
                syscall_command_category.handle_command(args, process)
            }
        }
    }
}

impl SyscallCommandCategory {
    pub fn handle_command(&self, args: Vec<String>, process: &mut Process) -> Result<()> {
        match self {
            SyscallCommandCategory::Clear => {
                process.set_syscall_catch_policy(libsdb::process::SyscallCatchPolicyMode::None);
            }
            SyscallCommandCategory::Specific => {
                let mut syscalls_to_catch = Vec::new();
                for arg in args {
                    if let Ok(num) = arg.parse::<usize>() {
                        if let Some(syscall) = Sysno::new(num) {
                            syscalls_to_catch.push(syscall);
                        } else {
                            return Err(anyhow::anyhow!("Invalid syscall number: {}", num));
                        }
                    } else if let Some(syscall) = Sysno::from_str(&arg).ok() {
                        syscalls_to_catch.push(syscall);
                    } else {
                        return Err(anyhow::anyhow!("Invalid syscall name or number: {}", arg));
                    }
                }
                // De-duplicate syscall numbers
                syscalls_to_catch.sort();
                syscalls_to_catch.dedup();
                println!(
                    "Catching syscalls: {:?}",
                    syscalls_to_catch
                        .iter()
                        .map(|num| Sysno::new(*num as usize).unwrap().name())
                        .collect::<Vec<&str>>()
                );
                process.set_syscall_catch_policy(libsdb::process::SyscallCatchPolicyMode::Some(
                    syscalls_to_catch,
                ));
            }
            SyscallCommandCategory::All => {
                process.set_syscall_catch_policy(libsdb::process::SyscallCatchPolicyMode::All);
            }
        }
        Ok(())
    }
}
