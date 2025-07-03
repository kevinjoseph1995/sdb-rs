use std::io::{Write, stdout};

use nix::sys::signal::raise;

fn main() {
    let stack_variable: u64 = 0xdeadbeef;
    let address = &stack_variable as *const u64;
    print!("{:p}", address);
    stdout().flush().unwrap();
    raise(nix::sys::signal::Signal::SIGTRAP).unwrap();

    const ARRAY_SIZE: usize = 12;
    type ArrayType = [u8; ARRAY_SIZE];
    let mut input_array: ArrayType = [0; ARRAY_SIZE];
    const _: () =
        assert!(std::mem::size_of::<ArrayType>() == ARRAY_SIZE * std::mem::size_of::<u8>());
    let input_array_ptr: *mut ArrayType = &mut input_array;
    print!("{:p}", input_array_ptr);
    stdout().flush().unwrap();
    raise(nix::sys::signal::Signal::SIGTRAP).unwrap();
    let string = String::from_utf8(input_array.to_vec()).unwrap();
    print!("{}", string);
}
