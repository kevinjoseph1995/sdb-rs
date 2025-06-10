use anyhow::Result;
use libsdb::process::Process;
use rustyline::{
    Context, Helper, completion::Completer, highlight::Highlighter, hint::Hinter,
    history::DefaultHistory, validate::Validator,
};
use std::path::PathBuf;

use crate::command::{self, Command, SubCommand, get_command_from_string};

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
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let _ = (line, pos, ctx);
        let line_components: Vec<&str> = line.trim().split_whitespace().collect();
        if line_components.is_empty() {
            return Ok((0, vec![]));
        } else if line_components.len() == 1 {
            let candidates: Vec<Self::Candidate> =
                command::get_candidates_for_given_prefix(line_components[0])
                    .into_iter()
                    .map(|c| c.to_string())
                    .collect();
            return Ok((0, candidates));
        } else {
            let command = match command::get_command_from_string(line_components[0]) {
                Some(command) => command,
                None => {
                    // If the command is not recognized, return an empty list of candidates
                    return Ok((0, vec![]));
                }
            };
            let args = &line_components[1..];
            /*
            Given the following defintion of a sub-command:

            pub struct SubCommand {
                pub sub_commands: &'static [SubCommand],
                ...
            }

            We need to handle the completion of sub-commands. We need to match every arg against the recursive sub-commands and return the candidates for the last arg.
             */
            let mut sub_commands = &command.metadata.sub_commands;
            for arg in args[..args.len() - 1].iter() {
                if let Some(sub_command) = sub_commands.iter().find(|&sc| sc.aliases.contains(&arg))
                {
                    // If we found a matching sub-command, we continue to the next argument
                    // and update the sub_commands to the sub_commands of the found sub_command
                    sub_commands = &sub_command.sub_commands;
                } else {
                    break;
                }
            }
            let candidates: Vec<String> = sub_commands
                .iter()
                .map(|s| s.aliases)
                .flatten()
                .filter(|alias| alias.starts_with(line_components.last().unwrap_or(&"")))
                .map(|alias| alias.to_string())
                .collect();
            return Ok((
                pos - line_components.last().unwrap_or(&"").len(),
                candidates,
            ));
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
        assert_eq!(
            command.metadata.category,
            command::CommandCategory::Register
        );
        todo!()
    }

    fn handle_help_command(&mut self, command: Command) -> Result<()> {
        assert_eq!(command.metadata.category, command::CommandCategory::Help);
        if command.args.is_empty() {
            // Show usage of all commands
            println!("Available commands:");
            for cmd in command::COMMANDS {
                println!("  {}: {}", cmd.aliases[0], cmd.description);
            }
        } else {
            // Show usage of a specific command
            if let Some(description) = command::get_full_command_description(&command.args) {
                println!("{}", description);
            } else {
                println!("Command '{}' not found.", command.args[0]);
            }
        }
        Ok(())
    }

    fn handle_command(&mut self, command: Command) -> Result<()> {
        match command.metadata.category {
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
            command::CommandCategory::Register => self.handle_register_command(command),
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
                    if let Some(command) = get_command_from_string(&line) {
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
