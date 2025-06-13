use anyhow::Result;
use libsdb::process::Process;
use rustyline::{
    Context, Helper, completion::Completer, highlight::Highlighter, hint::Hinter,
    history::DefaultHistory, validate::Validator,
};
use std::path::PathBuf;

use crate::command::{self, Command, RegisterCommandCategory};

pub struct Application {
    history_file: PathBuf,
    loop_running: bool,
    inferior_process: Process,
}

struct CustomHelper {
    // Custom helper fields can be added here
}

impl Validator for CustomHelper {}

impl Highlighter for CustomHelper {}

impl Hinter for CustomHelper {
    type Hint = String;
}

impl Completer for CustomHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let candidates = command::get_completions(line)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let white_space_pos = line[..pos].rfind(char::is_whitespace);
        if let Some(white_space_pos) = white_space_pos {
            return Ok((white_space_pos + 1, candidates));
        } else {
            return Ok((0, candidates));
        }
    }
}

impl Helper for CustomHelper {}

impl Application {
    pub fn new(inferior_process: Process) -> Self {
        Self {
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

    fn handle_register_command(&mut self, command: Command) -> Result<()> {
        todo!()
    }

    fn handle_help_command(&mut self, command: Command) -> Result<()> {
        let description = command::get_description_for_help(&command)?;
        println!("{}", description);
        Ok(())
    }

    fn handle_command(&mut self, command: Command) -> Result<()> {
        let category = command
            .metadata
            .category
            .expect("Command category should always be present");
        match category {
            command::CommandCategory::Exit => {
                println!("Exiting the debugger.");
                self.loop_running = false;
                Ok(())
            }
            command::CommandCategory::Run | command::CommandCategory::Continue => {
                self.inferior_process.resume_process().unwrap_or_else(|e| {
                    // Not a hard error, just print and continue
                    println!("Failed to resume process: {}", e);
                });
                Ok(())
            }
            command::CommandCategory::DumpChildOutput => {
                self.inferior_process
                    .print_child_output()
                    .unwrap_or_else(|e| {
                        // Not a hard error, just print and continue
                        println!("Failed to print child output: {}", e);
                    });
                Ok(())
            }
            command::CommandCategory::Help => self.handle_help_command(command),
            command::CommandCategory::Register(_) => self.handle_register_command(command),
        }
    }

    pub fn main_loop(&mut self) -> Result<()> {
        let mut rl = rustyline::Editor::<CustomHelper, DefaultHistory>::new()?;
        rl.set_helper(Some(CustomHelper {}));
        if rl.load_history(&self.history_file).is_ok() {
            println!("History loaded from: {}", self.history_file.display());
        } else {
            println!("No history file found, starting fresh.");
        }
        while self.loop_running {
            let readline = rl.readline("(sdb) ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str())?;
                    if let Ok(command) = Command::parse(&line) {
                        self.handle_command(command)?;
                    } else {
                        println!("Command not recognized: {}", line.trim());
                    }
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    self.inferior_process.stop_process()?;
                }
                Err(rustyline::error::ReadlineError::Eof) => {
                    println!("Ctrl-D pressed, exiting...");
                    self.loop_running = false;
                }
                Err(err) => {
                    eprintln!("Error reading line: {}", err);
                    self.loop_running = false;
                }
            }
        }

        anyhow::Ok(())
    }
}
