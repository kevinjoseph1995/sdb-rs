use std::io::Write;
use std::{ffi::c_int, io::stdout};

use nix::sys::signal::raise;

unsafe extern "C" {
    fn an_innocent_function();
    fn print_address_of_an_innocent_function();
    fn checksum() -> c_int;
}

fn main() {
    unsafe {
        let checksum_original = checksum();
        print_address_of_an_innocent_function();
        raise(nix::sys::signal::Signal::SIGTRAP).unwrap();
        loop {
            if checksum() == checksum_original {
                an_innocent_function();
            } else {
                println!("Checksum mismatch");
                stdout().flush().unwrap();
            }

            raise(nix::sys::signal::Signal::SIGTRAP).unwrap();
        }
    }
}
