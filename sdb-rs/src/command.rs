use lazy_static::lazy_static;
use ptrie::Trie;

#[derive(Debug, PartialEq)]
pub struct SubCommand {
    pub name: &'static str,
    pub description: &'static str,
    pub aliases: &'static [&'static str],
    pub sub_commands: &'static [SubCommand],
}

pub struct CommandMetadata {
    pub category: CommandCategory,
    pub description: &'static str,
    pub aliases: &'static [&'static str],
    pub sub_commands: &'static [SubCommand],
}

macro_rules! define_commands {
    ($(($cat:ident, $desc:expr, [$($alias:expr),*], [$($sub_cmd:expr),*])),*) => {
        #[derive(Debug, PartialEq, Hash)]
        pub enum CommandCategory {
            $($cat,)*
        }

        pub const COMMANDS: &[CommandMetadata] = &[
            $(CommandMetadata {
                category: CommandCategory::$cat,
                description: $desc,
                aliases: &[$($alias),*],
                sub_commands: &[$($sub_cmd),*],
            },)*
        ];
    };
}

macro_rules! subcommand {
    ($name:expr, $desc:expr, [$($alias:expr),*], [$($sub_cmd:expr),*]) => {
        SubCommand {
            name: $name,
            description: $desc,
            aliases: &[$($alias),*],
            sub_commands: &[$($sub_cmd),*],
        }
    };
}

define_commands!(
    (
        Exit,
        "Exit the debugger. Usage: `exit | quit | q`",
        ["exit", "quit", "q"],
        []
    ),
    (
        Run,
        "Run the inferior process. Usage: `run | r`",
        ["run", "r"],
        []
    ),
    (
        Continue,
        "Continue execution. Usage: `continue | c`",
        ["continue", "c"],
        []
    ),
    (
        DumpChildOutput,
        "Dump child output. Usage: `dump_child_output | dco`",
        ["dump_child_output", "dco"],
        []
    ),
    (
        Help,
        "Show help information. Usage: `help | h`",
        ["help", "h"],
        []
    ),
    (
        Register,
        "Read or write registers.",
        ["register", "reg"],
        [
            subcommand!(
                "read",
                "Read a register value. Usage: `register read <reg_name> [all]`",
                ["read", "r"],
                []
            ),
            subcommand!(
                "write",
                "Write a value to a register. Usage: `register write <reg_name> <value>`",
                ["write", "w"],
                []
            )
        ]
    )
);

lazy_static! {
    static ref COMMAND_TRIE: Trie<char, &'static CommandMetadata> = {
        let mut trie = Trie::new();
        for command in COMMANDS {
            for alias in command.aliases {
                trie.insert(alias.chars(), command);
            }
        }
        trie
    };
    static ref COMMAND_STRING_TRIE: Trie<char, &'static str> = {
        let mut trie = Trie::new();
        for command in COMMANDS {
            for alias in command.aliases {
                trie.insert(alias.chars(), *alias);
            }
        }
        trie
    };
}

pub struct Command {
    pub metadata: &'static CommandMetadata,
    pub args: Vec<String>,
}

/// Parses a command string and returns a `Command` struct if the command is valid.
/// For example, if the command string is "register read all", it will return a `Command` with the metadata for the "register" command and the args `["read", "all"]`.
pub fn get_command_from_string(command_string: &str) -> Option<Command> {
    let mut iter = command_string.split_whitespace();
    let alias = iter.next()?;
    let metadata = COMMAND_TRIE.get(alias.chars()).map(|&metadata| metadata)?;
    let args: Vec<String> = iter.map(String::from).collect();
    Some(Command { metadata, args })
}

/// Returns a list of command aliases that match the given prefix.
pub fn get_candidates_for_given_prefix(prefix: &str) -> Vec<&'static str> {
    COMMAND_STRING_TRIE
        .find_postfixes(prefix.chars())
        .into_iter()
        .map(|s| *s)
        .collect()
}

/// Returns a full command description including sub-commands if available.
/// If the command is not found, it returns None.
/// If the command has sub-commands, it appends their descriptions as well.
pub fn get_full_command_description(command_components: &Vec<String>) -> Option<String> {
    if command_components.is_empty() {
        return None;
    }
    let alias = command_components[0].as_str();
    let metadata = COMMAND_TRIE.get(alias.chars())?;
    let mut description = metadata.description.to_string();
    if command_components.len() == 1 {
        // Append available sub-commands if there are any
        if !metadata.sub_commands.is_empty() {
            description.push_str("\nAvailable sub-commands:");
            for sub_command in metadata.sub_commands {
                description.push_str(&format!(
                    "\n  {}: {}",
                    sub_command.name, sub_command.description
                ));
            }
        }
    }
    if command_components.len() > 1 {
        // If there are sub-commands, we need to find the sub-command and append its description
        let subcommand_strings = &command_components[1..];
        let mut sub_commands = &metadata.sub_commands;
        let mut index: usize = 0;
        loop {
            if index >= subcommand_strings.len() || sub_commands.is_empty() {
                // If we have exhausted the sub-commands or there are no sub-commands, we break
                break;
            }
            let subcommand_candidate = subcommand_strings[index].as_str();
            let matched_sub_command = sub_commands
                .iter()
                .find(|cmd| cmd.aliases.contains(&subcommand_candidate));
            if let Some(cmd) = matched_sub_command {
                description.push_str(&format!(
                    "\n{}{}: {}",
                    " ".repeat(index + 1),
                    cmd.name,
                    cmd.description
                ));
                sub_commands = &cmd.sub_commands;
                index += 1;
            } else {
                return None;
            }
        }
    }
    return Some(description);
}
