use crate::process::Process;
use anyhow::{Context, Result};
use libc::c_long;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtAddress {
    address: usize,
}

impl VirtAddress {
    pub fn new(address: usize) -> Self {
        VirtAddress { address }
    }
}

impl PartialOrd for VirtAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl Display for VirtAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.address)
    }
}

pub type StopPointId = i32;

pub struct BreakpointSite {
    id: StopPointId,
    is_enabled: bool,
    virtual_address: VirtAddress,
    saved_data: Option<u8>,
}

impl BreakpointSite {
    fn get_next_id() -> StopPointId {
        static NEXT_ID: std::sync::Mutex<StopPointId> = std::sync::Mutex::new(0);
        let mut id = NEXT_ID.lock().unwrap();
        let next_id = *id;
        *id += 1;
        next_id
    }

    pub fn new(virtual_address: VirtAddress) -> Self {
        BreakpointSite {
            id: BreakpointSite::get_next_id(),
            is_enabled: false,
            virtual_address,
            saved_data: None,
        }
    }
}

pub trait StopPoint {
    fn get_id(&self) -> StopPointId;

    fn enable(&mut self, process_handle: &Process) -> Result<()>;

    fn disable(&mut self, process_handle: &Process) -> Result<()>;

    fn is_enabled(&self) -> bool;

    fn get_virtual_address(&self) -> VirtAddress;

    fn in_range(&self, low: VirtAddress, high: VirtAddress) -> bool;

    fn is_at_address(&self, address: VirtAddress) -> bool;
}

impl StopPoint for BreakpointSite {
    fn enable(&mut self, process_handle: &Process) -> Result<()> {
        if self.is_enabled {
            return Ok(());
        }
        // Read a word from the process memory at the breakpoint address
        let data =
            nix::sys::ptrace::read(process_handle.pid, self.virtual_address.address as *mut _)
                .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))?;
        self.saved_data = Some((data as u64 & 0xFFu64) as u8);
        const INT3: u8 = 0xCC; // Breakpoint instruction
        let data_with_int3: u64 = (data as u64 & !0xFFu64) | INT3 as u64;
        // Write the breakpoint instruction to the process memory
        nix::sys::ptrace::write(
            process_handle.pid,
            self.virtual_address.address as *mut _,
            data_with_int3 as c_long,
        )
        .context("Failed to write memory")?;
        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self, process_handle: &Process) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }
        let data =
            nix::sys::ptrace::read(process_handle.pid, self.virtual_address.address as *mut _)
                .map_err(|e| anyhow::anyhow!("Failed to read memory: {}", e))?;
        let restored_word = (data as u64 & !0xFFu64)
            | self.saved_data.expect("saved_data should be present") as u64;
        // Write the original instruction back to the process memory
        nix::sys::ptrace::write(
            process_handle.pid,
            self.virtual_address.address as *mut _,
            restored_word as c_long,
        )
        .context("Disabling breakpoint failed. Failed to write memory")?;
        self.is_enabled = false;
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn get_virtual_address(&self) -> VirtAddress {
        self.virtual_address
    }

    fn in_range(&self, low: VirtAddress, high: VirtAddress) -> bool {
        self.virtual_address >= low && self.virtual_address < high
    }

    fn is_at_address(&self, address: VirtAddress) -> bool {
        self.virtual_address == address
    }

    fn get_id(&self) -> StopPointId {
        self.id
    }
}

pub struct StopPointCollection<T: StopPoint> {
    stop_points: Vec<T>,
}

impl<T: StopPoint> StopPointCollection<T> {
    pub fn new() -> Self {
        StopPointCollection {
            stop_points: Vec::new(),
        }
    }

    pub fn push(&mut self, stop_point: T) {
        self.stop_points.push(stop_point);
    }

    /// Push a stop point and return a mutable reference to element that was just pushed.
    pub fn push_and_return_mut_ref(&mut self, stop_point: T) -> Option<&mut T> {
        self.stop_points.push(stop_point);
        self.stop_points.last_mut()
    }

    /// Push a stop point and return an immutable reference to element that was just pushed.
    pub fn push_and_return_ref(&mut self, stop_point: T) -> Option<&T> {
        self.stop_points.push(stop_point);
        self.stop_points.last()
    }

    pub fn contains_id(&self, id: StopPointId) -> bool {
        self.stop_points.iter().any(|sp| sp.get_id() == id)
    }

    pub fn contains_address(&self, address: VirtAddress) -> bool {
        self.stop_points.iter().any(|sp| sp.is_at_address(address))
    }

    pub fn is_enabled_at_address(&self, address: VirtAddress) -> bool {
        self.stop_points
            .iter()
            .any(|sp| sp.is_at_address(address) && sp.is_enabled())
    }

    pub fn get_stop_point_by_id(&self, id: StopPointId) -> Option<&T> {
        self.stop_points.iter().find(|sp| sp.get_id() == id)
    }

    pub fn get_stop_point_by_id_mut(&mut self, id: StopPointId) -> Option<&mut T> {
        self.stop_points.iter_mut().find(|sp| sp.get_id() == id)
    }

    pub fn get_stop_point_by_address(&self, address: VirtAddress) -> Option<&T> {
        self.stop_points.iter().find(|sp| sp.is_at_address(address))
    }

    pub fn get_stop_point_by_address_mut(&mut self, address: VirtAddress) -> Option<&mut T> {
        self.stop_points
            .iter_mut()
            .find(|sp| sp.is_at_address(address))
    }

    pub fn remove_stop_point_by_id(&mut self, id: StopPointId) -> Option<T> {
        if let Some(pos) = self.stop_points.iter().position(|sp| sp.get_id() == id) {
            Some(self.stop_points.remove(pos))
        } else {
            None
        }
    }

    pub fn remove_stop_point_by_address(&mut self, address: VirtAddress) -> Option<T> {
        if let Some(pos) = self
            .stop_points
            .iter()
            .position(|sp| sp.is_at_address(address))
        {
            Some(self.stop_points.remove(pos))
        } else {
            None
        }
    }

    pub fn size(&self) -> usize {
        self.stop_points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stop_points.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.stop_points.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_next_id() {
        assert_eq!(BreakpointSite::get_next_id(), 0);
        assert_eq!(BreakpointSite::get_next_id(), 1);
        assert_eq!(BreakpointSite::get_next_id(), 2);
        assert_eq!(BreakpointSite::get_next_id(), 3);
        assert_eq!(BreakpointSite::get_next_id(), 4);
        assert_eq!(BreakpointSite::get_next_id(), 5);
    }
}
