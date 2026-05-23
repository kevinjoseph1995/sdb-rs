unsafe extern "C" {
    fn entry_a() -> i32;
    fn entry_b() -> i64;
}

fn main() {
    let a = unsafe { entry_a() };
    let b = unsafe { entry_b() };
    std::process::exit(((a as i64).wrapping_add(b) & 0xff) as i32);
}
