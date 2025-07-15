/////////////////////////////////////////
use std::iter::Peekable;
/////////////////////////////////////////
use anyhow::{Ok, Result};
/////////////////////////////////////////
pub mod breakpoint_command;
pub mod disassemble_command;
pub mod memory_command;
pub mod register_command;
/////////////////////////////////////////
use breakpoint_command::BreakpointCommandCategory;
use memory_command::MemoryCommandCategory;
use register_command::RegisterCommandCategory;
/////////////////////////////////////////

#[derive(Debug, Clone)]
pub struct OptionMetadata {
    pub aliases: &'static [&'static str],
    pub is_required: bool,
    pub _description: &'static str,
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
            _description: $desc,
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
    Watchpoint(WatchpointCommandCategory),
}

use BreakpointCommandCategory::*;
use CommandCategory::*;

use crate::command::breakpoint_command::WatchpointCommandCategory;

const COMMAND_METADATA_LIST: &[CommandMetadata] = &[
    cmd!(["run", "r"], "Run the program", [], Some(Run), None, []),
    cmd!(
        ["c", "continue"],
        "Continue execution",
        [],
        Some(Continue),
        None,
        []
    ),
    cmd!(
        ["quit", "exit", "q"],
        "Exit the debugger",
        [],
        Some(Exit),
        None,
        []
    ),
    cmd!(
        ["register", "reg"],
        "Register operations",
        [
            cmd!(
                ["read", "r"],
                "Read registers. Usage: 'register read all' or 'register read <register_name>'",
                [],
                Some(Register(RegisterCommandCategory::Read)),
                Some(&["<register_name>"]),
                []
            ),
            cmd!(
                ["write", "w"],
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
        ["dump_child_output", "dco"],
        "Dump child process output",
        [],
        Some(DumpChildOutput),
        None,
        []
    ),
    cmd!(
        ["breakpoint", "b"],
        "Breakpoint operations",
        [
            cmd!(
                ["list", "l"],
                "List all breakpoints. Usage: 'breakpoint list'",
                [],
                Some(Breakpoint(List)),
                None,
                []
            ),
            cmd!(
                ["info", "i"],
                "Get information about a specific breakpoint. Usage: 'breakpoint info <breakpoint_id>'",
                [],
                Some(Breakpoint(Info)),
                Some(&["<breakpoint_id>"]),
                []
            ),
            cmd!(
                ["set", "s"],
                "Set a new breakpoint. Usage: 'breakpoint set <address>'",
                [],
                Some(Breakpoint(Set)),
                Some(&["<address in hex>"]),
                []
            ),
            cmd!(
                ["set_hardware", "sh"],
                "Set a new hardware breakpoint. Usage: 'breakpoint set_hardware <address>'",
                [],
                Some(Breakpoint(SetHardware)),
                Some(&["<address in hex>"]),
                []
            ),
            cmd!(
                ["remove", "rm"],
                "Remove a breakpoint. Usage: 'breakpoint remove <breakpoint_id>'",
                [],
                Some(Breakpoint(Remove)),
                Some(&["<breakpoint_id>"]),
                []
            ),
            cmd!(
                ["enable", "e"],
                "Enable a breakpoint. Usage: 'breakpoint enable <breakpoint_id>'",
                [],
                Some(Breakpoint(Enable)),
                Some(&["<breakpoint_id>"]),
                []
            ),
            cmd!(
                ["disable", "d"],
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
                ["read", "r"],
                "Read memory. Usage: 'memory read <address> [<size>]'",
                [],
                Some(Memory(MemoryCommandCategory::Read)),
                Some(&["<address>", "[<size>]"]),
                []
            ),
            cmd!(
                ["write", "w"],
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
                false,
                "-a <address> | --address <address> (in hex format)"
            ),
            opt!(
                ["-n", "--number"],
                "Number of instructions to disassemble",
                false,
                "-n <number> | --number <number> (default is 10)"
            ),
        ]
    ),
    cmd!(
        ["watchpoint", "w"],
        "Watchpoint operations",
        [
            cmd!(
                ["list", "l"],
                "List all watchpoints. Usage: 'watchpoint list'",
                [],
                Some(Watchpoint(WatchpointCommandCategory::List)),
                None,
                []
            ),
            cmd!(
                ["info", "i"],
                "Get information about a specific watchpoint. Usage: 'watchpoint info <watchpoint_id>'",
                [],
                Some(Watchpoint(WatchpointCommandCategory::Info)),
                Some(&["<watchpoint_id>"]),
                []
            ),
            cmd!(
                ["set", "s"],
                "Set a new watchpoint. Usage: 'watchpoint set <address> <mode> <size>'. w = Write, rw = Read/Write, x = Execute",
                [],
                Some(Watchpoint(WatchpointCommandCategory::Set)),
                Some(&["<address in hex>", "w | rw | x", "<size>"]),
                []
            ),
            cmd!(
                ["remove", "rm"],
                "Remove a watchpoint. Usage: 'watchpoint remove <watchpoint_id>'",
                [],
                Some(Watchpoint(WatchpointCommandCategory::Remove)),
                Some(&["<watchpoint_id>"]),
                []
            ),
            cmd!(
                ["enable", "e"],
                "Enable a watchpoint. Usage: 'watchpoint enable <watchpoint_id>'",
                [],
                Some(Watchpoint(WatchpointCommandCategory::Enable)),
                Some(&["<watchpoint_id>"]),
                []
            ),
            cmd!(
                ["disable", "d"],
                "Disable a watchpoint. Usage: 'watchpoint disable <watchpoint_id>'",
                [],
                Some(Watchpoint(WatchpointCommandCategory::Disable)),
                Some(&["<watchpoint_id>"]),
                []
            ),
        ],
        None,
        None,
        []
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
    pub parsed_nodes: Vec<ParseChainNode>,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedOption {
    pub metadata: &'static OptionMetadata,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct ParseChainNode {
    pub metadata: &'static CommandMetadata,
    pub parsed_options: Vec<ParsedOption>,
}

#[derive(Debug, Clone)]
pub struct PotentialParseChainNode {
    pub metadata: &'static CommandMetadata,
    pub parsed_options: Vec<(String, String)>,
}

impl PotentialParseChainNode {
    fn convert_to_parse_chain_node(self) -> Result<ParseChainNode> {
        // Perform all the validation checks
        let command_metadata = self.metadata;
        let all_options = self.parsed_options;
        // Check if required options are present
        for option_metadata in command_metadata.options {
            if option_metadata.is_required
                && !all_options
                    .iter()
                    .any(|(opt, _)| option_metadata.aliases.contains(&opt.as_str()))
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
                .any(|opt| opt.aliases.contains(&option.as_str()))
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
                    .find(|opt| opt.aliases.contains(&option.as_str()))
                    .expect("Option metadata not found");
                ParsedOption {
                    metadata: option_metadata,
                    value,
                }
            })
            .collect();
        Ok(ParseChainNode {
            metadata: command_metadata,
            parsed_options,
        })
    }
}

fn try_consume_options<'a>(
    token_iterator: &mut Peekable<impl Iterator<Item = &'a str>>,
) -> Vec<(String, String)> {
    let mut potential_options: Vec<(String, String)> = Vec::new();
    loop {
        let current_token = match token_iterator.peek() {
            Some(t) => *t,
            None => {
                break;
            }
        };
        if current_token.starts_with('-') || current_token.starts_with("--") {
            let option = token_iterator.next().unwrap(); // Consume the option token
            let option_value = match token_iterator.next() {
                Some(value) => value,
                None => {
                    break;
                }
            };
            potential_options.push((option.to_string(), option_value.to_string()));
        } else {
            break; // No more options
        }
    }
    return potential_options;
}

/// A best effort to traverse the command tree and parse the input.
/// It does not return any errors, but instead returns a list of potential
/// parse nodes and any remaining unparsed tokens.
/// This is useful for command completion and help commands.
pub fn try_traverse_command_tree(input: &str) -> (Vec<PotentialParseChainNode>, Vec<String>) {
    let mut parse_chain = Vec::new();
    let mut token_iterator = input
        .trim_start()
        .split_whitespace()
        .map(|str| str.trim())
        .peekable();
    let mut current_command_level = COMMAND_METADATA_LIST;
    loop {
        let current_token = match token_iterator.peek() {
            Some(t) => *t,
            None => {
                break;
            }
        };
        let command_metadata = match current_command_level.iter().find_map(|cmd| {
            if cmd.aliases.contains(&current_token) {
                Some(cmd)
            } else {
                None
            }
        }) {
            Some(cmd) => cmd,
            None => break,
        };
        // At this stage we've mapped the current token to a command. Consume the token and move to the next level
        token_iterator.next();
        let potential_options = try_consume_options(&mut token_iterator);
        parse_chain.push(PotentialParseChainNode {
            metadata: command_metadata,
            parsed_options: potential_options,
        });
        if command_metadata.subcommands.is_empty() {
            // We've reached the end of the command tree
            break;
        } else {
            // Traverse the command tree hierarchy
            current_command_level = command_metadata.subcommands;
        }
    }
    return (
        parse_chain,
        token_iterator.map(String::from).collect::<Vec<String>>(),
    );
}

fn validate_parse_chain(parse_chain: &[ParseChainNode]) -> Result<()> {
    if parse_chain.is_empty() {
        return Err(anyhow::anyhow!("Parse chain is empty"));
    }
    let terminal_parse_node = parse_chain.last().unwrap();
    if !terminal_parse_node.metadata.subcommands.is_empty() {
        return Err(anyhow::anyhow!(
            "Incomplete command: expected subcommand for '{}'",
            terminal_parse_node.metadata.name
        ));
    }
    Ok(())
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
            parsed_nodes: vec![ParseChainNode {
                metadata: &HELP_COMMAND_METADATA,
                parsed_options: Vec::new(),
            }],
            args: rest.trim().split_whitespace().map(String::from).collect(),
        });
    }
    let (potential_parse_chain, remaining_args) = try_traverse_command_tree(input);
    let parse_chain: Vec<ParseChainNode> = potential_parse_chain
        .into_iter()
        .map(|node| node.convert_to_parse_chain_node())
        .collect::<Result<Vec<_>>>()?;
    validate_parse_chain(&parse_chain)?;
    Ok(Command {
        parsed_nodes: parse_chain,
        args: remaining_args,
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
    assert!(
        help_command
            .parsed_nodes
            .last()
            .expect("No command in parse chain")
            .metadata
            .category
            == Some(Help)
    );
    if help_command.args.is_empty() {
        let mut description = String::from("Available commands:");
        for command in COMMAND_METADATA_LIST {
            description.push_str(&format!("\n  {}: {}", command.name, command.description));
        }
        return Ok(description);
    }
    let (parse_chain, _) = try_traverse_command_tree(&help_command.args.join(" "));
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
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
                .metadata
                .category,
            Some(Register(RegisterCommandCategory::Read))
        );
        assert_eq!(
            parse("reg w")
                .expect("Unable to parse command")
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
                .metadata
                .category,
            Some(Register(RegisterCommandCategory::Write))
        );
        assert_eq!(
            parse("run")
                .expect("Unable to parse command")
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
                .metadata
                .category,
            Some(Run)
        );
        assert_eq!(
            parse("continue")
                .expect("Unable to parse command")
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
                .metadata
                .category,
            Some(Continue)
        );
        assert_eq!(
            parse("q")
                .expect("Unable to parse command")
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
                .metadata
                .category,
            Some(Exit)
        );
        assert_eq!(
            parse("dco")
                .expect("Unable to parse command")
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
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
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
                .metadata
                .category,
            Some(Help)
        );
        assert_eq!(
            parse("help reg")
                .expect("Unable to parse command")
                .parsed_nodes
                .last()
                .expect("No command in parse chain")
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

    fn validate_options_at_level(cmd: &[CommandMetadata]) {
        let mut options_at_level = std::collections::HashSet::new();
        for command in cmd {
            for option in command.options {
                for option_alias in option.aliases {
                    assert!(
                        options_at_level.insert(option_alias),
                        "Duplicate option alias found: {}",
                        option_alias
                    );
                    assert!(!option_alias.is_empty(), "Option alias cannot be empty");
                    assert!(
                        option_alias.starts_with('-') || option_alias.starts_with("--"),
                        "Option alias must start with '-' or '--': {}",
                        option_alias
                    );
                }
            }
            validate_level(command.subcommands);
        }
    }

    #[test]
    fn test_options_at_all_levels() {
        validate_options_at_level(&[HELP_COMMAND_METADATA]);
    }
}
