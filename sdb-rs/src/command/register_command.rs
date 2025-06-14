use libsdb::{
    process::Process,
    register_info::{REGISTER_INFO_TABLE, get_register_info_by_name},
};

use crate::command::CommandMetadata;
use anyhow::{Ok, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterCommandCategory {
    Read,
    Write,
}

impl RegisterCommandCategory {
    pub fn handle_register_read_command(
        &self,
        metadata: &CommandMetadata,
        args: Vec<String>,
        process: &Process,
    ) -> Result<()> {
        let registers = process.get_registers();
        if args.is_empty() || args[0] == "all" {
            // Print all registers
            REGISTER_INFO_TABLE.iter().for_each(|register_info| {
                let register_value = registers.get_register_value(register_info.id).expect(
                    format!("Failed to get value for register: {}", register_info.name).as_str(),
                );
                println!("{}: {}", register_info.name, register_value);
            });
            Ok(())
        } else if args.len() == 1 {
            // Print specific register
            let register_name = args[0].as_str();
            let register_info = match get_register_info_by_name(register_name) {
                Some(info) => info,
                None => {
                    return Err(anyhow::anyhow!(
                        "Register '{}' not found in the register table",
                        register_name
                    ));
                }
            };
            let register_value = registers.get_register_value(register_info.id).expect(
                format!("Failed to get value for register: {}", register_info.name).as_str(),
            );
            println!("{}: {}", register_info.name, register_value);
            Ok(())
        } else {
            // Invalid command usage
            return Err(anyhow::anyhow!(
                "Invalid command usage {}",
                metadata.description
            ));
        }
    }

    pub fn handle_register_write_command(
        &self,
        metadata: &CommandMetadata,
        args: Vec<String>,
        process: &mut Process,
    ) -> Result<()> {
        todo!()
    }

    pub fn handle_command(
        &self,
        metadata: &CommandMetadata,
        args: Vec<String>,
        process: &mut Process,
    ) -> Result<()> {
        match self {
            RegisterCommandCategory::Read => {
                self.handle_register_read_command(metadata, args, process)
            }
            RegisterCommandCategory::Write => {
                self.handle_register_write_command(metadata, args, process)
            }
        }
    }
}
