use std::os::fd::{AsFd, OwnedFd};
/////////////////////////////////////////
use anyhow::{Context, Result};

use nix::fcntl::OFlag;

pub struct ReadPort {
    fd: OwnedFd,
}

pub struct WritePort {
    fd: OwnedFd,
}

pub trait ChannelPort {
    fn into_internal_fd(self) -> OwnedFd;
}

impl ChannelPort for ReadPort {
    fn into_internal_fd(self) -> OwnedFd {
        return self.fd;
    }
}
impl ChannelPort for WritePort {
    fn into_internal_fd(self) -> OwnedFd {
        return self.fd;
    }
}

pub fn create_pipe_channel(close_on_exec: bool) -> Result<(ReadPort, WritePort)> {
    let (read_fd, write_fd) = nix::unistd::pipe2(if close_on_exec {
        OFlag::O_CLOEXEC
    } else {
        OFlag::empty()
    })
    .context("Failed to create pipe")?;

    Ok((ReadPort { fd: read_fd }, WritePort { fd: write_fd }))
}

impl ReadPort {
    pub fn read_into_buffer(&self, buf: &mut [u8]) -> Result<usize> {
        let bytes_read =
            nix::unistd::read(self.fd.as_fd(), buf).context("Failed to read from pipe")?;
        Ok(bytes_read)
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; 1024];
        let bytes_read = self.read_into_buffer(&mut buf)?;
        buf.truncate(bytes_read);
        Ok(buf)
    }
}

impl WritePort {
    pub fn write_from_buffer(&self, buf: &[u8]) -> Result<usize> {
        let bytes_written = nix::unistd::write(&self.fd, buf).context("Failed to write to pipe")?;
        Ok(bytes_written)
    }
}
