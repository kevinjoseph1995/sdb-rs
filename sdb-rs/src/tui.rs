/////////////////////////////////
use anyhow::Result;
use libsdb::process::Process;
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
    inferior_process: Process,
}

impl Application {
    pub fn new(options: Options, inferior_process: Process) -> Self {
        Self {
            _command_line_options: options,
            history_file: {
                match dirs::cache_dir() {
                    Some(cache_dir) => cache_dir.join(".sdb_history"),
                    None => PathBuf::from(".").join(".sdb_history"),
                }
            },
            inferior_process,
            loop_running: true,
        }
    }

    fn handle_command(&mut self, command: String) -> Result<()> {
        match command.as_str() {
            "exit" | "quit" | "q" => {
                self.loop_running = false;
                Ok(())
            }
            "run" | "r" | "continue" | "c" => {
                self.inferior_process.resume_process().unwrap_or_else(|e| {
                    // Not a hard error, just print and continue
                    println!("Failed to resume process: {}", e);
                });
                Ok(())
            }
            "dump_child_output" | "dco" => {
                self.inferior_process
                    .print_child_output()
                    .unwrap_or_else(|e| {
                        // Not a hard error, just print and continue
                        println!("Failed to print child output: {}", e);
                    });
                Ok(())
            }
            _ => {
                println!("Command not recognized: {}", command);
                Ok(())
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
                    self.handle_command(line.clone())?;
                }
                Err(ReadlineError::Interrupted) => {
                    self.inferior_process.stop_process()?;
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
