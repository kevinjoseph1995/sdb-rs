pub struct CommandMetadataComponent {
    pub aliases: &'static [&'static str],
    pub description: &'static str,
    pub sub_components: &'static [CommandMetadataComponent],
    pub max_arguments: u8
}

macro_rules! cmd {
    ([$($alias:expr),*], $desc:expr, [$($sub_cmd:expr),*], $max_args:expr) => {
        CommandMetadataComponent {
            aliases: &[$($alias),*],
            description: $desc,
            sub_components: &[$($sub_cmd),*],
            max_arguments: $max_args
        }
    };
}

macro_rules! command_table {
    ($(([$($alias:expr),*], $desc:expr, [$($sub_cmd:expr),*], $max_args:expr)),*) => {
        pub const COMMAND_TABLE: &[CommandMetadataComponent] = &[
            $(cmd!([$($alias),*], $desc, [$($sub_cmd),*], $max_args),)*
        ];
    };
}

command_table!(
    (["exit", "quit", "q"], "Exit the debugger.", [], 0),
    (["run", "r", "q"], "Run the inferior process.", [], 0),
    (["continue", "c"], "Continue execution.", [], 0),
    (["help", "h"], "Show help information for commands", [], 0),
    (
        ["register", "reg"],
        "Read/Write registers",
        [
            cmd!(["read", "r"], "Read a specific register value or all register values.", [], 2),
            cmd!(["write", "w"], "Write a register value", [], 1)
        ],0
    )
);
