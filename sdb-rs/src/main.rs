///////////////////////////
mod command;
mod options;
mod tui;
///////////////////////////
use clap::Parser;
///////////////////////////
use libsdb::{Pid, target::Target};
use options::Options;
///////////////////////////

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    let target: Target = {
        if let Some(pid) = options.pid {
            Target::attach(Pid::from_raw(pid))?
        } else if let Some(executable_path) = &options.executable {
            Target::launch(executable_path, options.program_args.clone(), true, None)?
        } else {
            unreachable!(
                "This should never happen because of the required_unless_present attribute"
            );
        }
    };
    {
        // Set up Ctrl-C handler to send SIGINT to the inferior process
        let pid = target.process.pid;
        ctrlc::try_set_handler(move || {
            nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGSTOP)
                .expect("Failed to send SIGSTOP to the process");
            println!("\nCtrl-C received, stopping the process...");
        })
        .expect("Error setting Ctrl-C handler");
    }

    let result = tui::Application::new(target).main_loop();
    if result.is_err() {
        eprintln!("Error in main loop: {}", result.unwrap_err());
        std::process::exit(1);
    }
    Ok(())
}
