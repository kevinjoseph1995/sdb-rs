/////////////////////////////////////////
use anyhow::{Context, Result};
use zydis::VisibleOperands;
/////////////////////////////////////////
use crate::address::VirtAddress;
use crate::process::Process;
/////////////////////////////////////////

#[derive(Debug)]
pub struct Instruction {
    pub address: VirtAddress,
    pub text: String,
}

mod detail {

    use super::*;

    pub fn disassemble(
        bytes: &[u8],
        start_offset: Option<VirtAddress>,
    ) -> Result<Vec<Instruction>> {
        let decoder = zydis::Decoder::new64();
        let mut instructions = Vec::new();

        for instr in decoder.decode_all::<VisibleOperands>(bytes, 0) {
            let (instr_offset, _instr_bytes, instruction) = match instr {
                Ok((instr_ptr, instr_bytes, instruction)) => (instr_ptr, instr_bytes, instruction),
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to decode instruction {}", err));
                }
            };
            instructions.push(Instruction {
                address: start_offset.unwrap_or(VirtAddress::from(0)) + (instr_offset as usize),
                text: instruction.to_string(),
            });
        }
        Ok(instructions)
    }
}

/// Disassemble a given number of instructions from the process at the specified address.
/// If no address is provided, it defaults to the current instruction pointer.
/// Returns a vector of `Instruction` objects containing the address and disassembled text.
/// /// # Arguments
/// * `process` - The process to disassemble instructions from.
/// * `number_of_instructions` - The number of instructions to disassemble.
/// * `address` - Optional address to start disassembling from. If None,
///               it defaults to the current instruction pointer of the process.
/// # Returns
/// * `Result<Vec<Instruction>>` - A vector of disassembled instructions
pub fn disassemble(
    process: &Process,
    number_of_instructions: usize,
    address: Option<VirtAddress>,
) -> Result<Vec<Instruction>> {
    let address = {
        if address.is_none() {
            process
                .get_pc()
                .context("Failed to get program counter since no address was provided")?
        } else {
            address.unwrap()
        }
    };
    const SIZE_OF_LARGEST_X64_INSTRUCTION: usize = 15;
    let code_bytes = process
        .read_memory_without_breakpoint_traps(
            address,
            SIZE_OF_LARGEST_X64_INSTRUCTION * number_of_instructions,
        )
        .context("Failed to read memory for disassembly")?;

    let mut instructions = detail::disassemble(&code_bytes, Some(address))?;
    instructions.truncate(number_of_instructions); // Limit to the requested number of instructions
    return Ok(instructions);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_nop() {
        let bytes = vec![0x90, 0x90, 0x90]; // NOP instructions
        let instructions = detail::disassemble(&bytes, None).unwrap();
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].text, "nop");
        assert_eq!(instructions[1].text, "nop");
        assert_eq!(instructions[2].text, "nop");
    }

    #[test]
    fn test_disassemble_basic() {
        let bytes: &[u8] = &[
            0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x48, 0x31, 0xc0, 0x50, 0x48,
            0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x53, 0x48, 0x89, 0xe7, 0xb0,
            0x3b, 0x0f, 0x05,
        ];
        let instructions = detail::disassemble(bytes, None).unwrap();
        // Taken from the really cool zydis playground!
        // https://zydis.re/
        let expected = vec![
            "xor rdi, rdi",
            "xor rsi, rsi",
            "xor rdx, rdx",
            "xor rax, rax",
            "push rax",
            "mov rbx, 0x68732F2F6E69622F",
            "push rbx",
            "mov rdi, rsp",
            "mov al, 0x3B",
            "syscall",
        ];
        assert_eq!(instructions.len(), expected.len());
        for (i, instruction) in instructions.iter().enumerate() {
            assert_eq!(instruction.text, expected[i]);
        }
    }

    #[test]
    fn test_disassemble_invalid() {
        let bytes = &[0xff, 0xff, 0xff]; // Invalid instruction bytes
        let result = detail::disassemble(bytes, None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Failed to decode instruction"));
        }
    }
}
