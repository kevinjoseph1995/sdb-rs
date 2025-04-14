fn main() {
    loop {
        println!("Hello!");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
