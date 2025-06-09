use std::fmt::Display;

use lazy_static::lazy_static;
use ptrie::Trie;

pub struct Command {
    pub category: CommandCategory,
    pub description: &'static str,
    pub aliases: &'static [&'static str],
}

macro_rules! define_commands {
    ($(($cat:ident, $desc:expr, [$($alias:expr),*])),*) => {
        #[derive(Debug)]
        pub enum CommandCategory {
            $($cat,)*
        }

        pub const COMMANDS: &[Command] = &[
            $(Command {
                category: CommandCategory::$cat,
                description: $desc,
                aliases: &[$($alias),*],
            },)*
        ];
    };
}

define_commands!(
    (Exit, "Exit the debugger.", ["exit", "quit", "q"]),
    (Run, "Run the inferior process.", ["run", "r"]),
    (Continue, "Continue execution.", ["continue", "c"]),
    (
        DumpChildOutput,
        "Dump child output.",
        ["dump_child_output", "dco"]
    )
);

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
