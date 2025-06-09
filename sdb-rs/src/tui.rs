use anyhow::Result;
use libsdb::process::Process;
use rustyline::{
    Context, Helper, completion::Completer, highlight::Highlighter, hint::Hinter,
    history::DefaultHistory, validate::Validator,
};
use std::path::PathBuf;

use crate::command::{self, Command, get_command_by_alias};

pub struct Application {
    history_file: PathBuf,
    loop_running: bool,
    inferior_process: Process,
}

struct CommandWithArgs {
    command: &'static Command,
    args: Vec<String>,
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
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let _ = (line, pos, ctx);
        let candidates: Vec<Self::Candidate> = command::get_candidates_for_given_prefix(line)
            .into_iter()
            .map(|c| c.to_string())
            .collect();
        Ok((0, candidates))
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

    fn handle_command(&mut self, command: &Command) -> Result<()> {
        match command.category {
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
                    if let Some(command) = get_command_by_alias(line.trim()) {
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
