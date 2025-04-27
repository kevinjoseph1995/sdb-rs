fn main() {
    let mut counter = 0;
    loop {
        println!("Hello! {}", counter);
        counter += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
