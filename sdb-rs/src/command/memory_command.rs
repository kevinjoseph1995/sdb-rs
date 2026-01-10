use anyhow::Result;
use libsdb::address::VirtAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryCommandCategory {
    Read,
    Write,
}

fn handle_read_command(args: Vec<String>, process: &libsdb::process::Process) -> Result<()> {
    if args.len() > 2 {
        return Err(anyhow::anyhow!(format!(
            "Invalid number of arguments for read command: expected atleast 1, got {}. Usage: <address> [<size>]",
            args.len()
        )));
    }
    let address: usize = {
        if args[0].starts_with("0x") || args[0].starts_with("0X") {
            usize::from_str_radix(&args[0][2..], 16)
                .map_err(|_| anyhow::anyhow!("Failed to parse address: {}", args[0]))?
        } else {
            args[0].parse().map_err(|_| {
                anyhow::anyhow!(format!(
                    "Invalid address argument: {}. Address must be a valid integer.",
                    args[0]
                ))
            })?
        }
    };
    let size: usize = {
        if args.len() == 2 {
            // Assume the size is base 10
            args[1].parse().map_err(|_| {
                anyhow::anyhow!(format!(
                    "Invalid size argument: {}. Size must be a valid integer.",
                    args[1]
                ))
            })?
        } else {
            32 // Default size if not specified
        }
    };

    let bytes = process
        .read_memory(VirtAddress::new(address), size)
        .map_err(|e| {
            anyhow::anyhow!(format!(
                "Failed to read memory at address 0x{:X} with size {}: {}",
                address, size, e
            ))
        })?;

    let mut chunk_start_address = address;
    bytes.chunks(16).for_each(|chunk| {
        let chunk_string: String = chunk
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ");
        // Optionally, you can also print the address of the chunk
        println!("0x{:x}: {}", chunk_start_address, chunk_string);
        chunk_start_address += chunk.len(); // Update address for next chunk if needed
    });
    Ok(())
}

fn handle_write_command(args: Vec<String>, process: &mut libsdb::process::Process) -> Result<()> {
    if args.len() < 2 {
        return Err(anyhow::anyhow!(format!(
            "Invalid number of arguments for write command: expected at least 2, got {}. Usage: <address> <value> [<value>...]",
            args.len()
        )));
    }

    let address: usize = {
        if args[0].starts_with("0x") || args[0].starts_with("0X") {
            usize::from_str_radix(&args[0][2..], 16)
                .map_err(|_| anyhow::anyhow!("Failed to parse address: {}", args[0]))?
        } else {
            args[0].parse().map_err(|_| {
                anyhow::anyhow!(format!(
                    "Invalid address argument: {}. Address must be a valid integer.",
                    args[0]
                ))
            })?
        }
    };

    let values: Vec<u8> = args[1..]
        .iter()
        .map(|arg| {
            if arg.starts_with("0x") || arg.starts_with("0X") {
                u8::from_str_radix(&arg[2..], 16)
                    .map_err(|_| anyhow::anyhow!("Failed to parse byte value: {}", arg))
            } else {
                arg.parse().map_err(|_| {
                    anyhow::anyhow!(format!(
                        "Invalid byte value argument: {}. Value must be a valid integer.",
                        arg
                    ))
                })
            }
        })
        .collect::<Result<Vec<u8>>>()?;

    process
        .write_memory(VirtAddress::new(address), &values)
        .map_err(|e| {
            anyhow::anyhow!(format!(
                "Failed to write memory at address 0x{:X}: {}",
                address, e
            ))
        })?;

    Ok(())
}

impl MemoryCommandCategory {
    pub fn handle_command(
        &self,
        args: Vec<String>,
        process: &mut libsdb::process::Process,
    ) -> Result<()> {
        match self {
            MemoryCommandCategory::Read => handle_read_command(args, process),
            MemoryCommandCategory::Write => handle_write_command(args, process),
        }
    }
}
