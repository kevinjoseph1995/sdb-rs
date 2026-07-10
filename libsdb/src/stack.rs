use crate::address::FileAddress;
use crate::dwarf::DiePayload;
use crate::process::Process;
use crate::target::TargetState;
use anyhow::Context;
use anyhow::Result;
use std::cell::Cell;

pub struct Stack {
    inline_height: Cell<u32>,
}

impl Stack {
    pub fn new() -> Self {
        Self {
            inline_height: Cell::new(0),
        }
    }

    pub fn get_inline_height(&self) -> u32 {
        self.inline_height.get()
    }

    // Inline height starts at 0 (deepest inlined frame), then counts
    // consecutive frames whose low_pc matches the current PC.
    pub fn reset_inline_height(&self, state: &TargetState, process: &Process) -> Result<()> {
        let pc = state
            .get_pc_file_address(process)
            .context("Failed to get PC")?;
        let stack = self.inline_stack_at_address(state, pc);

        self.inline_height.set(
            stack
                .iter()
                .rev()
                .take_while(|entry| entry.low_pc().ok().as_ref() == Some(&pc))
                .count() as u32,
        );
        Ok(())
    }

    pub fn inline_stack_at_pc<'elf>(
        &self,
        state: &'elf TargetState,
        process: &Process,
    ) -> Result<Vec<DiePayload<'elf>>> {
        let pc = state
            .get_pc_file_address(process)
            .context("Failed to get PC")?;
        Ok(self.inline_stack_at_address(state, pc))
    }

    fn inline_stack_at_address<'elf>(
        &self,
        state: &'elf TargetState,
        pc: FileAddress<'elf>,
    ) -> Vec<DiePayload<'elf>> {
        match &state.dwarf {
            Some(dwarf) => dwarf.inline_stack_at_address(pc),
            None => Vec::new(),
        }
    }
}
