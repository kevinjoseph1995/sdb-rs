///////////////////////////
mod options;
mod tui;
///////////////////////////
use clap::Parser;
///////////////////////////
use libsdb::Pid;
use options::Options;
///////////////////////////

fn main() {
    let options = Options::parse();
    let inferior_process_id: Pid = {
        if let Some(pid) = options.pid {
            Pid::from_raw(pid)
        } else if let Some(executable_path) = &options.executable {
            match libsdb::launch_and_setup_inferior_process(executable_path, &options.program_args)
            {
                Ok(child_pid) => child_pid,
                Err(e) => {
                    eprintln!("Failed to launch inferior process: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            unreachable!(
                "This should never happen because of the required_unless_present attribute"
            );
        }
    };

    libsdb::attach_to_process(inferior_process_id).unwrap_or_else(|e| {
        eprintln!("Failed to attach to process: {}", e);
        std::process::exit(1);
    });

    let result = tui::Application::new(options, inferior_process_id).main_loop();
    if result.is_err() {
        eprintln!("Error in main loop: {}", result.unwrap_err());
        std::process::exit(1);
    }
}
