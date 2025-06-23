use super::CommandMetadata;
use anyhow::{Context, Ok, Result};
use libsdb::{
    breakpoint::{self, StopPoint},
    process::Process,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakpointCommandCategory {
    List,
    Info,
    Set,
    Remove,
}

impl BreakpointCommandCategory {
    pub fn handle_command(
        &self,
        metadata: &CommandMetadata,
        args: Vec<String>,
        process: &mut Process,
    ) -> Result<()> {
        match self {
            BreakpointCommandCategory::List => {
                if process.breakpoint_sites.is_empty() {
                    println!("No breakpoints set.");
                    return Ok(());
                }
                println!("Breakpoints:");
                for breakpoint in process.breakpoint_sites.iter() {
                    println!(
                        "{}: address = {}, {}",
                        breakpoint.get_id(),
                        breakpoint.get_virtual_address(),
                        if breakpoint.is_enabled() {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                }
                Ok(())
            }
            BreakpointCommandCategory::Info => {
                if args.is_empty() {
                    println!("{}", metadata.description);
                    return Ok(());
                }
                let break_point_id: i32 = args[0].parse().context("Invalid breakpoint ID")?;
                let breakpoint = process
                    .breakpoint_sites
                    .get_stop_point_by_id(break_point_id)
                    .ok_or(anyhow::Error::msg(format!(
                        "Breakpoint with ID {} not found",
                        break_point_id
                    )))?;
                println!(
                    "Breakpoint ID: {}, Address: {}, Status: {}",
                    breakpoint.get_id(),
                    breakpoint.get_virtual_address(),
                    if breakpoint.is_enabled() {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                Ok(())
            }
            BreakpointCommandCategory::Set => {
                println!("TODO: SET A BREAKPOINT");
                Ok(())
            }
            BreakpointCommandCategory::Remove => {
                println!("TODO: REMOVE A BREAKPOINT");
                Ok(())
            }
        }
    }
}
