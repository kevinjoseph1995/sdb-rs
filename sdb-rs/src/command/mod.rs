use std::iter::Peekable;
/////////////////////////////////////////
use anyhow::{Ok, Result};
/////////////////////////////////////////
pub mod breakpoint_command;
pub mod memory_command;
pub mod register_command;
/////////////////////////////////////////
use breakpoint_command::BreakpointCommandCategory;
use libsdb::process::Process;
use memory_command::MemoryCommandCategory;
use register_command::RegisterCommandCategory;
/////////////////////////////////////////

#[derive(Debug, Clone)]
pub struct OptionMetadata {
    pub aliases: &'static [&'static str],
    pub is_required: bool,
    pub description: &'static str,
    pub hint: &'static str,
}

#[derive(Debug, Clone)]
pub struct CommandMetadata {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
    pub subcommands: &'static [CommandMetadata],
    pub category: Option<CommandCategory>,
    pub hint: Option<&'static [&'static str]>,
    pub options: &'static [OptionMetadata],
}

macro_rules! cmd {
    ([$first_alias:expr $(, $alias:expr)*], $desc:expr, [$($sub:tt)*], $category:expr, $hint:expr, [$($opt:tt)*]) => {
        CommandMetadata {
            name: $first_alias,
            aliases: &[$first_alias $(, $alias)*],
            description: $desc,
            subcommands: &[$($sub)*],
            category: $category,
            hint: $hint,
            options: &[$($opt)*],
        }
    };
}

macro_rules! opt {
    ([$first_alias:expr $(, $alias:expr)*], $desc:expr, $is_required:expr, $hint:expr) => {
        OptionMetadata {
            aliases: &[$first_alias $(, $alias)*],
            is_required: $is_required,
            description: $desc,
            hint: $hint,
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
    Step,
    Memory(MemoryCommandCategory),
    Disassemble,
}

use BreakpointCommandCategory::*;
use CommandCategory::*;

const COMMAND_METADATA_LIST: &[CommandMetadata] = &[
    cmd!(["r", "run"], "Run the program", [], Some(Run), None, []),
    cmd!(
        ["c", "continue"],
        "Continue execution",
        [],
        Some(Continue),
        None,
        []
    ),
    cmd!(
        ["q", "quit", "exit"],
        "Exit the debugger",
        [],
        Some(Exit),
        None,
        []
    ),
    cmd!(
        ["reg", "register"],
        "Register operations",
        [
            cmd!(
                ["r", "read"],
                "Read registers. Usage: 'register read all' or 'register read <register_name>'",
                [],
                Some(Register(RegisterCommandCategory::Read)),
                Some(&["<register_name>"]),
                []
            ),
            cmd!(
                ["w", "write"],
                "Write to registers",
                [],
                Some(Register(RegisterCommandCategory::Write)),
                Some(&["<register_name>", "<value>"]),
                []
            ),
        ],
        None,
        None,
        []
    ),
    cmd!(
        ["dco", "dump_child_output"],
        "Dump child process output",
        [],
        Some(DumpChildOutput),
        None,
        []
    ),
    cmd!(
        ["b", "breakpoint"],
        "Breakpoint operations",
        [
            cmd!(
                ["l", "list"],
                "List all breakpoints. Usage: 'breakpoint list'",
                [],
                Some(Breakpoint(List)),
                None,
                []
            ),
            cmd!(
                ["i", "info"],
                "Get information about a specific breakpoint. Usage: 'breakpoint info <breakpoint_id>'",
                [],
                Some(Breakpoint(Info)),
                Some(&["<breakpoint_id>"]),
                []
            ),
            cmd!(
                ["s", "set"],
                "Set a new breakpoint. Usage: 'breakpoint set <address>'",
                [],
                Some(Breakpoint(Set)),
                Some(&["<address in hex>"]),
                []
            ),
            cmd!(
                ["rm", "remove"],
                "Remove a breakpoint. Usage: 'breakpoint remove <breakpoint_id>'",
                [],
                Some(Breakpoint(Remove)),
                Some(&["<breakpoint_id>"]),
                []
            ),
            cmd!(
                ["e", "enable"],
                "Enable a breakpoint. Usage: 'breakpoint enable <breakpoint_id>'",
                [],
                Some(Breakpoint(Enable)),
                Some(&["<breakpoint_id>"]),
                []
            ),
            cmd!(
                ["d", "disable"],
                "Disable a breakpoint. Usage: 'breakpoint disable <breakpoint_id>'",
                [],
                Some(Breakpoint(Disable)),
                Some(&["<breakpoint_id>"]),
                []
            ),
        ],
        None,
        None,
        []
    ),
    cmd!(
        ["step", "s"],
        "Step over a single instruction",
        [],
        Some(Step),
        None,
        []
    ),
    cmd!(
        ["memory", "m"],
        "Memory operations",
        [
            cmd!(
                ["r", "read"],
                "Read memory. Usage: 'memory read <address> [<size>]'",
                [],
                Some(Memory(MemoryCommandCategory::Read)),
                Some(&["<address>", "[<size>]"]),
                []
            ),
            cmd!(
                ["w", "write"],
                "Write to memory. Usage: 'memory write <address> [<value>, <value>...]'",
                [],
                Some(Memory(MemoryCommandCategory::Write)),
                Some(&["<address>", "<byte_value1_in_hex> <byte_value2_in_hex> ..."]),
                []
            ),
        ],
        None,
        None,
        []
    ),
    cmd!(
        ["disassemble", "d"],
        "Disassemble instructions at a given address",
        [],
        Some(Disassemble),
        None,
        [
            opt!(
                ["-a", "--address"],
                "Address to disassemble from",
                true,
                "-a <address> | --address <address> (in hex format)"
            ),
            opt!(
                ["-n", "--number"],
                "Number of instructions to disassemble",
                true,
                "-n <number> | --number <number> (default is 10)"
            ),
        ]
    ),
];

const HELP_COMMAND_METADATA: CommandMetadata = CommandMetadata {
    name: "help",
    aliases: &["h", "help"],
    description: "Show help information for commands",
    subcommands: &COMMAND_METADATA_LIST,
    category: Some(Help),
    hint: None,
    options: &[],
};

#[derive(Debug, Clone)]
pub struct Command {
    pub metadata: &'static CommandMetadata,
    pub args: Vec<String>,
}

pub struct ParsedOption {
    pub metadata: &'static OptionMetadata,
    pub value: String,
}

pub struct ParseChainNode {
    pub metadata: &'static CommandMetadata,
    pub parsed_options: Vec<ParsedOption>,
}

fn consume_options<'a>(
    token_iterator: &mut Peekable<impl Iterator<Item = &'a str>>,
    command_metadata: &CommandMetadata,
) -> Result<Vec<ParsedOption>> {
    if command_metadata.options.is_empty() {
        return Ok(Vec::new());
    }
    let mut all_options: Vec<(&str, &str)> = Vec::new();
    while let Some(token) = token_iterator.peek() {
        if token.starts_with('-') || token.starts_with("--") {
            let option = token_iterator.next().unwrap();
            let option_value = token_iterator
                .next()
                .ok_or(anyhow::anyhow!("Expected value for option: {}", option))?;
            all_options.push((option, option_value));
        } else {
            break; // No more options
        }
    }

    // Validation checks
    // Check if required options are present
    for option_metadata in command_metadata.options {
        if option_metadata.is_required
            && !all_options
                .iter()
                .any(|(opt, _)| option_metadata.aliases.contains(&opt))
        {
            return Err(anyhow::anyhow!(
                "Required option missing: {}",
                option_metadata.aliases.join(", ")
            ));
        }
    }
    // Check if any option is provided that is not defined in the command metadata
    for (option, _) in &all_options {
        if !command_metadata
            .options
            .iter()
            .any(|opt| opt.aliases.contains(&option))
        {
            return Err(anyhow::anyhow!(
                "Unknown option: {}. Available options: {:?}",
                option,
                command_metadata
                    .options
                    .iter()
                    .flat_map(|opt| opt.aliases)
                    .collect::<Vec<_>>()
            ));
        }
    }

    let parsed_options: Vec<ParsedOption> = all_options
        .into_iter()
        .map(|(option, value)| {
            let option_metadata = command_metadata
                .options
                .iter()
                .find(|opt| opt.aliases.contains(&option))
                .expect("Option metadata not found");
            ParsedOption {
                metadata: option_metadata,
                value: value.to_string(),
            }
        })
        .collect();

    Ok(parsed_options)
}

fn traverse_command_tree(input: &str) -> Result<(Vec<ParseChainNode>, Vec<String>)> {
    let mut parse_chain = Vec::new();
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
        let command_metadata = match current_command_level.iter().find_map(|cmd| {
            if cmd.aliases.contains(&token) {
                Some(cmd)
            } else {
                None
            }
        }) {
            Some(cmd) => cmd,
            None => return Err(anyhow::anyhow!("Unknown command: {}", token)),
        };
        let parsed_options = consume_options(&mut token_iterator, command_metadata)?;
        parse_chain.push(ParseChainNode {
            metadata: command_metadata,
            parsed_options,
        });
        if command_metadata.subcommands.is_empty() || token_iterator.peek().is_none() {
            return Ok((
                parse_chain,
                token_iterator.map(String::from).collect::<Vec<String>>(),
            ));
        } else {
            // Traverse the command tree hierarchy
            current_command_level = command_metadata.subcommands;
        }
    }
}

/// Parse the command input and return a Command struct.
/// Example:
/// ```
/// let command = parse("reg r rax").unwrap();
/// assert_eq!(command.metadata.name, "read");
/// assert_eq!(command.args, vec!["rax"]);
pub fn parse(input: &str) -> Result<Command> {
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
    let (parse_chain, args) = traverse_command_tree(input)?;
    let terminal_parse_node = parse_chain
        .last()
        .ok_or(anyhow::anyhow!("No command in parse chain"))?;
    Ok(Command {
        metadata: terminal_parse_node.metadata,
        args,
    })
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
    let (parse_chain, _) = traverse_command_tree(&help_command.args.join(" "))?;
    let terminal_parse_node = parse_chain
        .last()
        .ok_or(anyhow::anyhow!("No command in parse chain"))?;
    let mut description = format!(
        "{}: {}",
        terminal_parse_node.metadata.name, terminal_parse_node.metadata.description
    );
    if !terminal_parse_node.metadata.subcommands.is_empty() {
        description.push_str("\nAvailable sub-commands:");
        for sub_command in terminal_parse_node.metadata.subcommands {
            description.push_str(&format!(
                "\n  {}: {}",
                sub_command.name, sub_command.description
            ));
        }
    }
    return Ok(description);
}

pub trait CommandHandler {
    fn handle_command(
        &self,
        metadata: &CommandMetadata,
        args: Vec<String>,
        process: &mut Process,
    ) -> Result<()>;
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
            parse("reg r")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Register(RegisterCommandCategory::Read))
        );
        assert_eq!(
            parse("reg w")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Register(RegisterCommandCategory::Write))
        );
        assert_eq!(
            parse("run")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Run)
        );
        assert_eq!(
            parse("continue")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Continue)
        );
        assert_eq!(
            parse("q")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Exit)
        );
        assert_eq!(
            parse("dco")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(DumpChildOutput)
        );

        assert_eq!(
            parse("reg r rax").expect("Unable to parse command").args,
            vec!["rax"]
        );

        assert_eq!(
            parse("reg w rax 123")
                .expect("Unable to parse command")
                .args,
            vec!["rax", "123"]
        );

        assert_eq!(
            parse("help")
                .expect("Unable to parse command")
                .metadata
                .category,
            Some(Help)
        );
        assert_eq!(
            parse("help reg")
                .expect("Unable to parse command")
                .metadata
                .name,
            "help"
        );
        assert_eq!(
            parse("help reg").expect("Unable to parse command").args,
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
            let help_command = parse("help ").expect("Unable to parse command");
            let description =
                get_description_for_help(&help_command).expect("Unable to get description");
            assert!(description.contains("Available commands:"));
        }
        {
            let help_command = parse("help reg").expect("Unable to parse command");
            let description =
                get_description_for_help(&help_command).expect("Unable to get description");
            assert!(description.contains("Available sub-commands:"));
        }
        {
            let help_command = parse("help reg w").expect("Unable to parse command");
            let description =
                get_description_for_help(&help_command).expect("Unable to get description");
            assert!(!description.contains("Available commands:"));
            assert!(!description.contains("Available sub-commands:"));
        }
    }
}
