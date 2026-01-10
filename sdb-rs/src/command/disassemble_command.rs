use crate::command::{CommandCategory, ParsedOption};

use super::Command;
use anyhow::{Ok, Result};
use libsdb::address::VirtAddress;
use libsdb::process::Process;

pub fn print_disassembly(
    process: &Process,
    number_of_instructions: usize,
    address: Option<VirtAddress>,
) -> Result<()> {
    let instructions = libsdb::disassembler::disassemble(process, number_of_instructions, address)?;
    for instruction in instructions {
        println!("{}: {}", instruction.address, instruction.text);
    }
    Ok(())
}

pub fn handle_command(command: &Command, process: &Process) -> Result<()> {
    assert!(
        !command.parsed_nodes.is_empty(),
        "Command chain should not be empty"
    );
    assert!(
        command.parsed_nodes.len() == 1,
        "Command chain should have exactly one node"
    );
    let last_in_chain = command
        .parsed_nodes
        .last()
        .expect("No command in parse chain");
    assert!(
        last_in_chain.metadata.category == Some(CommandCategory::Disassemble),
        "Command category should be Disassemble"
    );
    let address = match last_in_chain.parsed_options.iter().find(|option| {
        option
            .metadata
            .aliases
            .iter()
            .any(|alias_arg| alias_arg.contains(&"address"))
    }) {
        Some(ParsedOption { value, metadata }) => {
            if value.is_empty() {
                return Err(anyhow::anyhow!(
                    "Option '{}' requires a value",
                    metadata.aliases.join(", ")
                ));
            }
            if !(value.starts_with("0x") || value.starts_with("0X")) {
                return Err(anyhow::anyhow!(
                    "Hex Address must start with '0x' or '0X': {}",
                    value
                ));
            }
            let address = usize::from_str_radix(&value[2..], 16)
                .map_err(|_| anyhow::anyhow!("Invalid hex address: {}", value))?;
            VirtAddress::new(address)
        }
        None => process.get_pc()?,
    };

    let number_of_instructions = match last_in_chain.parsed_options.iter().find(|option| {
        option
            .metadata
            .aliases
            .iter()
            .any(|alias_arg| alias_arg.contains(&"number"))
    }) {
        Some(ParsedOption { value, metadata }) => {
            if value.is_empty() {
                return Err(anyhow::anyhow!(
                    "Option '{}' requires a value",
                    metadata.aliases.join(", ")
                ));
            }
            value
                .parse::<usize>()
                .map_err(|_| anyhow::anyhow!("Invalid number of instructions: {}", value))?
        }
        None => 10, // Default to 10 instructions if not specified
    };
    print_disassembly(process, number_of_instructions, Some(address))
}
