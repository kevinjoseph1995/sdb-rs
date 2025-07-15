/////////////////////////////////////////
use anyhow::{Context, Ok, Result};
/////////////////////////////////////////
use super::CommandMetadata;
use libsdb::process::{Process, StopPointMode, VirtAddress};
/////////////////////////////////////////

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakpointCommandCategory {
    List,
    Info,
    Set,
    SetHardware,
    Enable,
    Disable,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchpointCommandCategory {
    List,
    Info,
    Set,
    Enable,
    Disable,
    Remove,
}

fn set_breakpoint(
    metadata: &CommandMetadata,
    args: Vec<String>,
    process: &mut Process,
    is_hardware: bool,
) -> Result<()> {
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
    let breakpoint = process.create_breakpoint(VirtAddress::from(address), true, is_hardware)?;
    println!(
        "Breakpoint set at address: {}, ID: {}",
        breakpoint.virtual_address(),
        breakpoint.id()
    );
    Ok(())
}

impl WatchpointCommandCategory {
    pub fn handle_command(
        &self,
        metadata: &CommandMetadata,
        args: Vec<String>,
        process: &mut Process,
    ) -> Result<()> {
        match self {
            WatchpointCommandCategory::List => {
                if process.watchpoints.is_empty() {
                    println!("No watchpoints set.");
                    return Ok(());
                }
                println!("Watchpoints:");
                for watchpoint in process.watchpoints.iter() {
                    println!(
                        "{}: address = {}, {}",
                        watchpoint.id(),
                        watchpoint.virtual_address(),
                        if watchpoint.is_enabled() {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                }
                Ok(())
            }
            WatchpointCommandCategory::Info => {
                if args.is_empty() {
                    println!("{}", metadata.description);
                    return Ok(());
                }
                let watchpoint_id: i32 = args[0].parse().context("Invalid watchpoint ID")?;
                let watchpoint = process
                    .watchpoints
                    .iter()
                    .find(|wp| wp.id() == watchpoint_id)
                    .ok_or(anyhow::Error::msg(format!(
                        "Watchpoint with ID {} not found.",
                        watchpoint_id
                    )))?;
                println!(
                    "Watchpoint ID: {}, Address: {}, Status: {} Mode: {:#?}",
                    watchpoint.id(),
                    watchpoint.virtual_address(),
                    if watchpoint.is_enabled() {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    watchpoint.mode()
                );
                Ok(())
            }
            WatchpointCommandCategory::Set => {
                if args.len() != 3 {
                    return Err(anyhow::Error::msg(format!(
                        "Invalid number of arguments. {}",
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
                let mode = match args[1].to_lowercase().as_str().trim() {
                    "x" => StopPointMode::Execute,
                    "w" => StopPointMode::Write,
                    "rw" => StopPointMode::ReadWrite,
                    _ => {
                        return Err(anyhow::Error::msg(format!(
                            "Invalid mode: {}. Mode should be one of x/w/rw.",
                            args[1]
                        )));
                    }
                };
                let size: u8 = args[2].parse().context("Invalid size")?;

                let watchpoint =
                    process.create_watchpoint(VirtAddress::from(address), size, mode, true)?;
                println!(
                    "Watchpoint set at address: {}, ID: {}",
                    watchpoint.virtual_address(),
                    watchpoint.id()
                );
                Ok(())
            }
            WatchpointCommandCategory::Enable => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a watchpoint ID to enable. {}",
                        metadata.description
                    )));
                }
                let watchpoint_id: i32 = args[0].parse().context("Invalid watchpoint ID")?;
                process
                    .enable_watchpoint_by_id(watchpoint_id)
                    .context(format!(
                        "Failed to enable watchpoint with ID {}.",
                        watchpoint_id
                    ))?;
                println!("Watchpoint enabled: ID {}", watchpoint_id);
                Ok(())
            }
            WatchpointCommandCategory::Disable => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a watchpoint ID to disable. {}",
                        metadata.description
                    )));
                }
                let watchpoint_id: i32 = args[0].parse().context("Invalid watchpoint ID")?;
                process
                    .disable_watchpoint_by_id(watchpoint_id)
                    .context(format!(
                        "Failed to disable watchpoint with ID {}.",
                        watchpoint_id
                    ))?;
                println!("Watchpoint disabled: ID {}", watchpoint_id);
                Ok(())
            }
            WatchpointCommandCategory::Remove => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a watchpoint ID. {}",
                        metadata.description
                    )));
                }
                let watchpoint_id: i32 = args[0].parse().context("Invalid watchpoint ID")?;
                if !process
                    .watchpoints
                    .iter()
                    .find(|wp| wp.id() == watchpoint_id)
                    .is_some()
                {
                    return Err(anyhow::Error::msg(format!(
                        "Watchpoint with ID {} not found.",
                        watchpoint_id
                    )));
                }
                process.remove_watchpoint_by_id(watchpoint_id)?;
                println!("Watchpoint removed: ID {}", watchpoint_id);
                Ok(())
            }
        }
    }
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
                if process.breakpoints.is_empty() {
                    println!("No breakpoints set.");
                    return Ok(());
                }
                println!("Breakpoints:");
                for breakpoint in process.breakpoints.iter() {
                    println!(
                        "{}: address = {}, {}",
                        breakpoint.id(),
                        breakpoint.virtual_address(),
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
                    .breakpoints
                    .iter()
                    .find(|bp| bp.id() == break_point_id)
                    .ok_or(anyhow::Error::msg(format!(
                        "Breakpoint with ID {} not found.",
                        break_point_id
                    )))?;
                println!(
                    "Breakpoint ID: {}, Address: {}, Status: {}",
                    breakpoint.id(),
                    breakpoint.virtual_address(),
                    if breakpoint.is_enabled() {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                Ok(())
            }
            BreakpointCommandCategory::Set => set_breakpoint(metadata, args, process, false),
            BreakpointCommandCategory::SetHardware => set_breakpoint(metadata, args, process, true),
            BreakpointCommandCategory::Remove => {
                if args.is_empty() {
                    return Err(anyhow::Error::msg(format!(
                        "Please specify a breakpoint ID. {}",
                        metadata.description
                    )));
                }
                let breakpoint_id: i32 = args[0].parse().context("Invalid breakpoint ID")?;
                if !process
                    .breakpoints
                    .iter()
                    .find(|bp| bp.id() == breakpoint_id)
                    .is_some()
                {
                    return Err(anyhow::Error::msg(format!(
                        "Breakpoint with ID {} not found.",
                        breakpoint_id
                    )));
                }
                process.remove_breakpoint_by_id(breakpoint_id)?;
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
                    .disable_breakpoint_by_id(breakpoint_id)
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
