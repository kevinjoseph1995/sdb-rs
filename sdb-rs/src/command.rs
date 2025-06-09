use std::fmt::Display;

use lazy_static::lazy_static;
use ptrie::Trie;

pub enum CommandCategory {
    Exit,
    Run,
    Continue,
    DumpChildOutput,
}
pub struct Command {
    pub category: CommandCategory,
    pub description: &'static str,
    pub aliases: &'static [&'static str],
}

pub const COMMANDS: &'static [Command] = &[
    Command {
        category: CommandCategory::Exit,
        description: "Exit the debugger.",
        aliases: &["exit", "quit", "q"],
    },
    Command {
        category: CommandCategory::Run,
        description: "Run the inferior process.",
        aliases: &["run", "r"],
    },
    Command {
        category: CommandCategory::Continue,
        description: "Continue the execution of the inferior process.",
        aliases: &["continue", "c"],
    },
    Command {
        category: CommandCategory::DumpChildOutput,
        description: "Dump the output of the child process.",
        aliases: &["dump_child_output", "dco"],
    },
];

lazy_static! {
    static ref COMMAND_TRIE: Trie<char, &'static Command> = {
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

pub fn get_command_by_alias(alias: &str) -> Option<&'static Command> {
    COMMAND_TRIE.get(alias.chars()).map(|&command| command)
}

pub fn get_candidates_for_given_prefix(prefix: &str) -> Vec<&'static str> {
    COMMAND_STRING_TRIE
        .find_postfixes(prefix.chars())
        .into_iter()
        .map(|s| *s)
        .collect()
}
