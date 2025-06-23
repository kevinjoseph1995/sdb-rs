pub mod breakpoint_command;
pub mod register_command;

use anyhow::{Ok, Result};
use breakpoint_command::BreakpointCommandCategory;
use register_command::RegisterCommandCategory;

#[derive(Debug, Clone)]
pub struct CommandMetadata {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
    pub subcommands: &'static [CommandMetadata],
    pub category: Option<CommandCategory>,
}

macro_rules! cmd {
    ([$first_alias:expr $(, $alias:expr)*], $desc:expr, [$($sub:tt)*], $category:expr) => {
        CommandMetadata {
            name: $first_alias,
            aliases: &[$first_alias $(, $alias)*],
            description: $desc,
            subcommands: &[$($sub)*],
            category: $category,
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandCategory {
    Exit,
    Run,
    Continue,
    Register(RegisterCommandCategory),
    DumpChildOutput,
    Breakpoint(BreakpointCommandCategory),
    Help,
}

use BreakpointCommandCategory::*;
use CommandCategory::*;
use RegisterCommandCategory::*;

const COMMAND_METADATA_LIST: &[CommandMetadata] = &[
    cmd!(["r", "run"], "Run the program", [], Some(Run)),
    cmd!(["c", "continue"], "Continue execution", [], Some(Continue)),
    cmd!(["q", "quit", "exit"], "Exit the debugger", [], Some(Exit)),
    cmd!(
        ["reg", "register"],
        "Register operations",
        [
            cmd!(
                ["r", "read"],
                "Read registers. Usage: 'register read all' or 'register read <register_name>'",
                [],
                Some(Register(Read))
            ),
            cmd!(
                ["w", "write"],
                "Write to registers",
                [],
                Some(Register(Write))
            ),
        ],
        None
    ),
    cmd!(
        ["dco", "dump_child_output"],
        "Dump child process output",
        [],
        Some(DumpChildOutput)
    ),
    cmd!(
        ["b", "breakpoint"],
        "Breakpoint operations",
        [
            cmd!(
                ["l", "list"],
                "List all breakpoints. Usage: 'breakpoint list'",
                [],
                Some(Breakpoint(List))
            ),
            cmd!(
                ["i", "info"],
                "Get information about a specific breakpoint. Usage: 'breakpoint info <breakpoint_id>'",
                [],
                Some(Breakpoint(Info))
            ),
            cmd!(
                ["s", "set"],
                "Set a new breakpoint. Usage: 'breakpoint set <address>'",
                [],
                Some(Breakpoint(Set))
            ),
            cmd!(
                ["rm", "remove"],
                "Remove a breakpoint. Usage: 'breakpoint remove <breakpoint_id>'",
                [],
                Some(Breakpoint(Remove))
            ),
        ],
        None
    ),
];

const HELP_COMMAND_METADATA: CommandMetadata = CommandMetadata {
    name: "help",
    aliases: &["h", "help"],
    description: "Show help information for commands",
    subcommands: &COMMAND_METADATA_LIST,
    category: Some(Help),
};

#[derive(Debug, Clone)]
pub struct Command {
    pub metadata: &'static CommandMetadata,
    pub args: Vec<String>,
}

impl Command {
    /// Traverse the command tree to find the command metadata
    /// and return the remaining arguments.
    fn traverse_command_tree(input: &str) -> Result<(&'static CommandMetadata, Vec<String>)> {
        let mut token_iterator = input
            .trim_start()
            .split_whitespace()
            .map(|str| str.trim())
            .peekable();
        let mut current_command_level = COMMAND_METADATA_LIST;
        loop {
            let token = match token_iterator.next() {
                Some(token) => token,
                None => return Err(anyhow::anyhow!("No command provided")),
            };
            let command = match current_command_level.iter().find_map(|cmd| {
                if cmd.aliases.contains(&token) {
                    Some(cmd)
                } else {
                    None
                }
            }) {
                Some(cmd) => cmd,
                None => return Err(anyhow::anyhow!("Unknown command: {}", token)),
            };
            if command.subcommands.is_empty() || token_iterator.peek().is_none() {
                return Ok((
                    command,
                    token_iterator.map(String::from).collect::<Vec<String>>(),
                ));
            } else {
                // Traverse the command tree hierarchy
                current_command_level = command.subcommands;
            }
        }
    }

    /// Parse the command input and return a Command struct.
    /// Example:
    /// ```
    /// let command = Command::parse("reg r rax").unwrap();
    /// assert_eq!(command.metadata.name, "read");
    /// assert_eq!(command.args, vec!["rax"]);
    pub fn parse(input: &str) -> Result<Self> {
        let (first_token, rest) = match input.find(|c: char| c.is_whitespace()) {
            Some(index) => {
                let first_token = &input[..index];
                let rest = &input[index..];
                (first_token, rest)
            }
            None => (input, ""),
        };
        if first_token == "help" || first_token == "h" {
            return Ok(Command {
                metadata: &HELP_COMMAND_METADATA,
                args: rest.trim().split_whitespace().map(String::from).collect(),
            });
        }
        let (command_metadata, args) = Self::traverse_command_tree(input)?;
        if !command_metadata.subcommands.is_empty() {
            return Err(anyhow::anyhow!(
                "Incomplete command: expected subcommand for '{}'",
                command_metadata.name
            ));
        }
        Ok(Command {
            metadata: command_metadata,
            args,
        })
    }
}

fn handle_completions_for_commands(
    mut partial_command_string: &str,
    commands: &[CommandMetadata],
) -> Vec<&'static str> {
    partial_command_string = partial_command_string.trim_start();
    if partial_command_string.is_empty() {
        return commands
            .iter()
            .map(|cmd| cmd.aliases)
            .flatten()
            .cloned()
            .collect();
    }
    let (first_token, rest) = match partial_command_string.find(|c: char| c.is_whitespace()) {
        Some(index) => {
            let first_token = &partial_command_string[..index];
            let rest = &partial_command_string[index..];
            (first_token, rest)
        }
        None => (partial_command_string, ""),
    };
    // Check if we have a matching command
    if let Some(command) = commands
        .iter()
        .find(|cmd| cmd.aliases.contains(&first_token))
    {
        if rest.is_empty() {
            return command.aliases.to_vec();
        } else {
            // If we have a matching command, check its subcommands
            return handle_completions_for_commands(rest, command.subcommands);
        }
    }
    // Check if we have a prefix match
    let mut completions = Vec::new();
    for command in commands {
        for alias in command.aliases {
            if alias.starts_with(first_token) {
                completions.push(*alias);
            }
        }
    }
    completions
}

pub fn get_completions(partial_command_string: &str) -> Vec<&'static str> {
    let (first_token, rest) = match partial_command_string.find(|c: char| c.is_whitespace()) {
        Some(index) => {
            let first_token = &partial_command_string[..index];
            let rest = &partial_command_string[index..];
            (first_token, rest)
        }
        None => (partial_command_string, ""),
    };

    if HELP_COMMAND_METADATA.aliases.contains(&first_token) {
        return handle_completions_for_commands(rest, COMMAND_METADATA_LIST);
    } else {
        return handle_completions_for_commands(partial_command_string, COMMAND_METADATA_LIST);
    }
}

pub fn get_description_for_help(help_command: &Command) -> Result<String> {
    assert!(help_command.metadata.category == Some(Help));
    if help_command.args.is_empty() {
        let mut description = String::from("Available commands:");
        for command in COMMAND_METADATA_LIST {
            description.push_str(&format!("\n  {}: {}", command.name, command.description));
        }
        return Ok(description);
    }
    let (metadata, _) = Command::traverse_command_tree(&help_command.args.join(" "))?;
    let mut description = format!("{}: {}", metadata.name, metadata.description);
    if !metadata.subcommands.is_empty() {
        description.push_str("\nAvailable sub-commands:");
        for sub_command in metadata.subcommands {
            description.push_str(&format!(
                "\n  {}: {}",
                sub_command.name, sub_command.description
            ));
        }
    }
    return Ok(description);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_level(cmd: &[CommandMetadata]) {
        let mut aliases = std::collections::HashSet::new();
        for command in cmd {
            for alias in command.aliases {
                assert!(aliases.insert(*alias), "Duplicate alias found: {}", alias);
            }
            validate_level(command.subcommands);
        }
    }

    #[test]
    fn test_unique_aliases_at_same_level() {
        assert!(
            COMMAND_METADATA_LIST
                .iter()
                .map(|cmd| cmd.aliases)
                .flatten()
                .filter(|alias| **alias == "help" || **alias == "h")
                .count()
                == 0
        );
        validate_level(COMMAND_METADATA_LIST);
    }

    #[test]
    fn test_command_parsing() {
        assert_eq!(
            Command::parse("reg r")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Register(Read))
        );
        assert_eq!(
            Command::parse("reg w")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Register(Write))
        );
        assert_eq!(
            Command::parse("run")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Run)
        );
        assert_eq!(
            Command::parse("continue")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Continue)
        );
        assert_eq!(
            Command::parse("q")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Exit)
        );
        assert_eq!(
            Command::parse("dco")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(DumpChildOutput)
        );

        assert_eq!(
            Command::parse("reg r rax")
                .expect("Unable to parse command")
                .args,
            vec!["rax"]
        );

        assert_eq!(
            Command::parse("reg w rax 123")
                .expect("Unable to parse command")
                .args,
            vec!["rax", "123"]
        );

        assert_eq!(
            Command::parse("help")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Help)
        );
        assert_eq!(
            Command::parse("help reg")
                .expect("Unable to parse command")
                .metadata
                .name,
            "help"
        );
        assert_eq!(
            Command::parse("help reg")
                .expect("Unable to parse command")
                .args,
            vec!["reg"]
        );
    }

    #[test]
    fn test_get_completions() {
        {
            let completions = get_completions("");
            assert!(completions.contains(&"run"));
            assert!(completions.contains(&"continue"));
            assert!(completions.contains(&"exit"));
            assert!(completions.contains(&"dump_child_output"));
            assert!(completions.contains(&"register"));
            assert!(!completions.contains(&"help")); // This is expected
        }
        {
            let completions = get_completions("help");
            assert!(completions.contains(&"run"));
            assert!(completions.contains(&"continue"));
            assert!(completions.contains(&"exit"));
            assert!(completions.contains(&"dump_child_output"));
            assert!(completions.contains(&"register"));
            assert!(!completions.contains(&"help")); // This is expected
        }
        {
            let completions = get_completions("re");
            assert!(completions.contains(&"reg"));
            assert!(completions.contains(&"register"));
        }
        {
            let completions = get_completions("reg");
            assert!(completions.contains(&"reg"));
            assert!(completions.contains(&"register"));
        }
        {
            let completions = get_completions("reg ");
            assert!(completions.contains(&"r"));
            assert!(completions.contains(&"read"));
            assert!(completions.contains(&"w"));
            assert!(completions.contains(&"write"));
        }

        {
            let completions = get_completions("help reg ");
            assert!(completions.contains(&"r"));
            assert!(completions.contains(&"read"));
            assert!(completions.contains(&"w"));
            assert!(completions.contains(&"write"));
        }
    }

    #[test]
    fn test_get_description_for_help() {
        {
            let help_command = Command::parse("help ").expect("Unable to parse command");
            let description =
                get_description_for_help(&help_command).expect("Unable to get description");
            assert!(description.contains("Available commands:"));
        }
        {
            let help_command = Command::parse("help reg").expect("Unable to parse command");
            let description =
                get_description_for_help(&help_command).expect("Unable to get description");
            assert!(description.contains("Available sub-commands:"));
        }
        {
            let help_command = Command::parse("help reg w").expect("Unable to parse command");
            let description =
                get_description_for_help(&help_command).expect("Unable to get description");
            assert!(!description.contains("Available commands:"));
            assert!(!description.contains("Available sub-commands:"));
        }
    }
}
