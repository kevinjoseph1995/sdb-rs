/////////////////////////////////
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::path::PathBuf;
/////////////////////////////////
use crate::options::Options;
/////////////////////////////////

pub struct Application {
    _command_line_options: Options,
    history_file: PathBuf,
    loop_running: bool,
    inferior_process_id: libsdb::Pid,
}

impl Application {
    pub fn new(options: Options, inferior_process_id: libsdb::Pid) -> Self {
        Self {
            _command_line_options: options,
            history_file: std::env::home_dir()
                .unwrap()
                .join(".cache")
                .join("sdb_history"),
            inferior_process_id,
            loop_running: true,
        }
    }

    fn handle_command(&mut self, command: String) {
        match command.as_str() {
            "exit" | "quit" | "q" => {
                self.loop_running = false;
            }
            "run" | "r" | "continue" | "c" => {
                libsdb::resume_process(self.inferior_process_id).unwrap_or_else(|e| {
                    println!("Failed to resume process: {}", e);
                });
            }
            _ => {
                println!("Command not recognized: {}", command);
            }
        }
    }

    pub fn main_loop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut rl = DefaultEditor::new()?;
        if rl.load_history(&self.history_file).is_err() {
            println!("No previous history.");
        }
        println!("{}", self.history_file.display());

        while self.loop_running {
            let readline = rl.readline("(sdb) ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str())?;
                    self.handle_command(line.clone());
                }
                Err(ReadlineError::Interrupted) => {
                    println!("CTRL-C");
                    break;
                }
                Err(ReadlineError::Eof) => {
                    println!("CTRL-D");
                    break;
                }
                Err(err) => {
                    eprintln!("Error: {:?}", err);
                    break;
                }
            }
        }
        rl.save_history(&self.history_file)?;
        Ok(())
    }
}
