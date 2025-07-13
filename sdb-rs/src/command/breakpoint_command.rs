/////////////////////////////////////////
use anyhow::{Context, Ok, Result};
/////////////////////////////////////////
use super::CommandMetadata;
use libsdb::process::{Process, VirtAddress};
/////////////////////////////////////////

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakpointCommandCategory {
    List,
    Info,
    Set,
    Enable,
    Disable,
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
                    .iter()
                    .find(|bp| bp.get_id() == break_point_id)
                    .ok_or(anyhow::Error::msg(format!(
                        "Breakpoint with ID {} not found.",
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
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "No address provided for breakpoint. {}",
                        metadata.description
                    )));
                }
                if !(args[0].starts_with("0x") || args[0].starts_with("0X")) {
                    return Err(anyhow::Error::msg(format!(
                        "Invalid address format: {}. Hex-address should start with 0x/0X.",
                        args[0]
                    )));
                }
                let address_str = &args[0][2..];
                let address = usize::from_str_radix(address_str, 16).map_err(|err| {
                    anyhow::Error::msg(format!(
                        "{}: Invalid address format: {}. Hex-address should be a valid hex number.",
                        err, args[0]
                    ))
                })?;
                let breakpoint = process.create_breakpoint_site(VirtAddress::from(address))?;
                println!(
                    "Breakpoint set at address: {}, ID: {}",
                    breakpoint.get_virtual_address(),
                    breakpoint.get_id()
                );
                Ok(())
            }
            BreakpointCommandCategory::Remove => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a breakpoint ID. {}",
                        metadata.description
                    )));
                }
                let breakpoint_id: i32 = args[0].parse().context("Invalid breakpoint ID")?;
                if !process
                    .breakpoint_sites
                    .iter()
                    .find(|bp| bp.get_id() == breakpoint_id)
                    .is_some()
                {
                    return Err(anyhow::Error::msg(format!(
                        "Breakpoint with ID {} not found.",
                        breakpoint_id
                    )));
                }
                process.remove_stop_point_by_id(breakpoint_id)?;
                println!("Breakpoint removed: ID {}", breakpoint_id);
                Ok(())
            }
            BreakpointCommandCategory::Enable => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a breakpoint ID to enable. {}",
                        metadata.description
                    )));
                }
                let breakpoint_id: i32 = args[0].parse().context("Invalid breakpoint ID")?;
                process
                    .enable_breakpoint_by_id(breakpoint_id)
                    .context(format!(
                        "Failed to enable breakpoint with ID {}.",
                        breakpoint_id
                    ))?;
                println!("Breakpoint enabled: ID {}", breakpoint_id);
                Ok(())
            }
            BreakpointCommandCategory::Disable => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a breakpoint ID to disable. {}",
                        metadata.description
                    )));
                }
                let breakpoint_id: i32 = args[0].parse().context("Invalid breakpoint ID")?;
                process
                    .disable_breakpoint_site(breakpoint_id)
                    .context(format!(
                        "Failed to disable breakpoint with ID {}.",
                        breakpoint_id
                    ))?;
                println!("Breakpoint disabled: ID {}", breakpoint_id);
                Ok(())
            }
        }
    }
}
