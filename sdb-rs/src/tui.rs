/////////////////////////////////////////
use std::{borrow::Cow, path::PathBuf};
/////////////////////////////////////////
use anyhow::Result;
use colored::Colorize;
use ctrlc::Signal;
use nix::sys::wait::WaitStatus;
use rustyline::{
    Config, Context, Helper, completion::Completer, highlight::Highlighter, hint::Hinter,
    history::DefaultHistory, validate::Validator,
};
/////////////////////////////////////////
use crate::command::{self, Command, CommandCategory, get_completions, get_description_for_help};
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

impl Highlighter for CustomHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Highlight the hint with ANSI color
        // Detect if the the terminal supports colors
        let colorized = hint.blue();
        Cow::Owned(colorized.to_string())
    }
}

impl Hinter for CustomHelper {
    type Hint = String;
    fn hint(&self, line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        let (parse_nodes, remaining_tokens) = crate::command::try_traverse_command_tree(line);
        if !remaining_tokens.is_empty() {
            // If there are remaining tokens, we can't provide a hint
            return None;
        }
        if let Some(last_char) = line.chars().last() {
            if !last_char.is_whitespace() {
                // If the last character is not whitespace, we can't provide a hint
                return None;
            }
        }
        let last_node = match parse_nodes.last() {
            Some(n) => n,
            None => return None,
        };
        // Option hinting
        if last_node.metadata.options.len() > 0 {
            // This command has options, so we can provide a hint
            let specified_options = &last_node.parsed_options;
            return Some(
                last_node
                    .metadata
                    .options
                    .iter()
                    .filter(|option| {
                        // Filter out options that are already specified
                        !specified_options
                            .iter()
                            .any(|(option_name, _)| option.aliases.contains(&option_name.as_str()))
                    })
                    .map(|option| option.hint)
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
        }
        // If the command itself has any hint, return that
        if let Some(hint_list) = last_node.metadata.hint {
            if remaining_tokens.len() < hint_list.len() && line.ends_with(char::is_whitespace) {
                return Some(hint_list[remaining_tokens.len()..].join(" ").to_string());
            }
        }
        // Subcommand hinting
        if last_node.metadata.subcommands.len() > 0 {
            // This command has subcommands, so we can provide a hint
            return Some(
                last_node
                    .metadata
                    .subcommands
                    .iter()
                    .map(|subcommand| subcommand.name)
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
        }
        return None;
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
        if self.inferior_process.get_state() == libsdb::process::ProcessHandleState::Stopped {
            command::disassemble_command::print_disassembly(
                &self.inferior_process,
                1,
                self.inferior_process.get_pc().ok(),
            )?;
        }
        Ok(())
    }

    fn handle_command(&mut self, command: Command) -> Result<()> {
        let last_in_chain = command
            .parsed_nodes
            .last()
            .expect("No command in parse chain");
        let category = last_in_chain
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
            CommandCategory::Register(cmd) => cmd.handle_command(
                last_in_chain.metadata,
                command.args,
                &mut self.inferior_process,
            ),
            CommandCategory::Breakpoint(cmd) => cmd.handle_command(
                &last_in_chain.metadata,
                command.args,
                &mut self.inferior_process,
            ),
            CommandCategory::Step => {
                self.inferior_process.single_step()?;
                if self.inferior_process.get_state() == libsdb::process::ProcessHandleState::Stopped
                {
                    command::disassemble_command::print_disassembly(
                        &self.inferior_process,
                        1,
                        self.inferior_process.get_pc().ok(),
                    )?;
                }
                Ok(())
            }
            CommandCategory::Memory(cmd) => {
                cmd.handle_command(command.args, &mut self.inferior_process)
            }
            CommandCategory::Disassemble => crate::command::disassemble_command::handle_command(
                &command,
                &self.inferior_process,
            ),
            CommandCategory::Watchpoint(watchpoint_command_category) => watchpoint_command_category
                .handle_command(
                    &last_in_chain.metadata,
                    command.args,
                    &mut self.inferior_process,
                ),
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
        let mut last_line = String::new();
        while self.loop_running {
            let readline = rl.readline("(sdb) ");
            match readline {
                Ok(mut line) => {
                    if line.trim().is_empty() {
                        // If the line is empty, use the last line. This is useful for repeating the last command by pressing Enter.
                        line = last_line;
                    }
                    rl.add_history_entry(line.as_str())?;
                    match crate::command::parse(&line) {
                        Ok(command) => {
                            if let Err(err) = self.handle_command(command) {
                                eprintln!("Error handling command: {}", err);
                            }
                        }
                        Err(err) => {
                            eprintln!("Error parsing command: {}", err);
                        }
                    }
                    last_line = line; // Store the last line for potential reuse
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
