/////////////////////////////////////////
use std::path::PathBuf;
/////////////////////////////////////////
use anyhow::Result;
use ctrlc::Signal;
use nix::sys::wait::WaitStatus;
use rustyline::{
    Config, Context, Helper, completion::Completer, highlight::Highlighter, hint::Hinter,
    history::DefaultHistory, validate::Validator,
};
/////////////////////////////////////////
use crate::command::{
    Command, CommandCategory, CommandHandler, get_completions, get_description_for_help,
};
use libsdb::process::Process;
/////////////////////////////////////////

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
    fn hint(&self, line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        if let Ok(command) = crate::command::parse(&line) {
            if let Some(hint_list) = command.metadata.hint {
                if command.args.len() < hint_list.len() && line.ends_with(char::is_whitespace) {
                    return Some(hint_list[command.args.len()..].join(" ").to_string());
                }
            }
        }
        None
    }
}

impl Completer for CustomHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let candidates = get_completions(line)
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

    fn handle_help_command(&mut self, command: Command) -> Result<()> {
        let description = get_description_for_help(&command)?;
        println!("{}", description);
        Ok(())
    }

    fn handle_stop_reason(&self, waitstatus: WaitStatus) -> Result<()> {
        match waitstatus {
            WaitStatus::Exited(_, exit_status) => {
                println!("Process exited with status: {}", exit_status);
            }
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                println!(
                    "Hit breakpoint at address: {}",
                    self.inferior_process.get_pc()?
                );
            }
            WaitStatus::Stopped(_, signal) => {
                println!("Process stopped by signal: {}", signal);
            }
            WaitStatus::Signaled(_, signal, _) => {
                println!("Process terminated by signal: {}", signal);
            }
            WaitStatus::Continued(_pid) => {
                println!("Process continued.");
            }
            WaitStatus::StillAlive => {
                println!("Process is still alive.");
            }
            _ => {
                println!("Unhandled wait status: {:?}", waitstatus);
            }
        }
        Ok(())
    }

    fn handle_command(&mut self, command: Command) -> Result<()> {
        let category = command
            .metadata
            .category
            .expect("Command category should always be present");
        match category {
            CommandCategory::Exit => {
                println!("Exiting the debugger.");
                self.loop_running = false;
                Ok(())
            }
            CommandCategory::Run | CommandCategory::Continue => {
                self.inferior_process.resume_process().unwrap_or_else(|e| {
                    // Not a hard error, just print and continue
                    println!("Failed to resume process: {}", e);
                });
                let stop_reason = self.inferior_process.wait_on_signal(None)?;
                self.handle_stop_reason(stop_reason)?;
                Ok(())
            }
            CommandCategory::DumpChildOutput => {
                self.inferior_process
                    .print_child_output()
                    .unwrap_or_else(|e| {
                        // Not a hard error, just print and continue
                        println!("Failed to print child output: {}", e);
                    });
                Ok(())
            }
            CommandCategory::Help => self.handle_help_command(command),
            CommandCategory::Register(cmd) => {
                cmd.handle_command(command.metadata, command.args, &mut self.inferior_process)
            }
            CommandCategory::Breakpoint(cmd) => {
                cmd.handle_command(&command.metadata, command.args, &mut self.inferior_process)
            }
            CommandCategory::Step => {
                self.inferior_process.single_step()?;
                Ok(())
            }
            CommandCategory::Memory(cmd) => {
                cmd.handle_command(&command.metadata, command.args, &mut self.inferior_process)
            }
        }
    }

    pub fn main_loop(&mut self) -> Result<()> {
        let mut rl = rustyline::Editor::<CustomHelper, DefaultHistory>::with_config(
            Config::builder().build(),
        )?;
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
                    if let Ok(command) = crate::command::parse(&line) {
                        if let Err(err) = self.handle_command(command) {
                            eprintln!("Error handling command: {}", err);
                        }
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
        rl.save_history(&self.history_file)?;

        anyhow::Ok(())
    }
}
