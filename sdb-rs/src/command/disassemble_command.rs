use std::path::Path;
use std::sync::OnceLock;

use crate::command::{CommandCategory, ParsedOption};

use super::Command;
use anyhow::{Ok, Result};
use colored::Colorize;
use libsdb::address::VirtAddress;
use libsdb::process::Process;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, Theme, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::{LinesWithEndings, as_24_bit_terminal_escaped};

pub fn print_disassembly(
    process: &Process,
    number_of_instructions: usize,
    address: Option<VirtAddress>,
) -> Result<()> {
    let instructions = libsdb::disassembler::disassemble(process, number_of_instructions, address)?;
    for instruction in instructions {
        println!(
            "{}: {}",
            instruction.address.to_string().yellow(),
            instruction.text
        );
    }
    Ok(())
}

/// Prints a `path:line` header, then `line` of the source file at `path` with
/// `context_number_of_lines` lines on either side, marking `line` with `>`.
/// The source is read from disk, so a missing file prints a note instead of
/// failing the stop.
pub fn print_source(path: &Path, line: usize, context_number_of_lines: usize) -> Result<()> {
    let source = match std::fs::read_to_string(path) {
        std::result::Result::Ok(source) => source,
        Err(error) => {
            println!("Could not read source file {}: {error}", path.display());
            return Ok(());
        }
    };
    // A line past the end means the file on disk no longer matches the
    // binary, so the window around it would show the wrong code.
    let line_count = LinesWithEndings::from(&source).count();
    if line > line_count {
        println!(
            "Line {line} is past the end of {} ({line_count} lines); the source may have changed since the build",
            path.display()
        );
        return Ok(());
    }
    println!("{}", format!("{}:{line}", path.display()).cyan());
    let start_line = line.saturating_sub(context_number_of_lines).max(1);
    let end_line = line + context_number_of_lines;
    let line_number_width = end_line.to_string().len();

    // Only highlight when `colored` would color output (stdout is a TTY and
    // NO_COLOR is unset), so piped output stays plain.
    let highlighter = colored::control::SHOULD_COLORIZE
        .should_colorize()
        .then(source_highlighter);
    let mut highlight_lines = highlighter.map(|highlighter| {
        let syntaxes = &highlighter.syntaxes;
        let syntax = path
            .extension()
            .and_then(|extension| extension.to_str())
            .and_then(|extension| syntaxes.find_syntax_by_extension(extension))
            .or_else(|| syntaxes.find_syntax_by_first_line(&source))
            .unwrap_or_else(|| syntaxes.find_syntax_plain_text());
        HighlightLines::new(syntax, &highlighter.theme)
    });

    for (index, text) in LinesWithEndings::from(&source).enumerate().take(end_line) {
        let line_number = index + 1;
        // The highlighter carries state across lines (block comments, raw
        // strings), so every line up to the window goes through it, not just
        // the ones we print.
        let ranges = match (&mut highlight_lines, highlighter) {
            (Some(highlight_lines), Some(highlighter)) => {
                Some(highlight_lines.highlight_line(text, &highlighter.syntaxes)?)
            }
            _ => None,
        };
        if line_number < start_line {
            continue;
        }
        let text = match ranges {
            Some(ranges) => {
                let ranges: Vec<(Style, &str)> = ranges
                    .into_iter()
                    .map(|(style, text)| (style, text.trim_end_matches(['\r', '\n'])))
                    .collect();
                format!("{}\x1b[0m", as_24_bit_terminal_escaped(&ranges, false))
            }
            None => text.trim_end_matches(['\r', '\n']).to_string(),
        };
        let arrow = if line_number == line { ">" } else { " " };
        println!(
            "{arrow} {} {text}",
            format!("{line_number:>line_number_width$}").yellow()
        );
    }
    Ok(())
}

struct SourceHighlighter {
    syntaxes: SyntaxSet,
    theme: Theme,
}

/// Loading syntect's bundled syntaxes takes tens of milliseconds, so it
/// happens once, on the first stop that shows source.
fn source_highlighter() -> &'static SourceHighlighter {
    static HIGHLIGHTER: OnceLock<SourceHighlighter> = OnceLock::new();
    HIGHLIGHTER.get_or_init(|| {
        let mut themes = ThemeSet::load_defaults().themes;
        SourceHighlighter {
            syntaxes: SyntaxSet::load_defaults_newlines(),
            theme: themes
                .remove("base16-ocean.dark")
                .expect("syntect bundles the base16-ocean.dark theme"),
        }
    })
}

pub fn handle_command(command: &Command, process: &Process) -> Result<()> {
    assert!(
        !command.parsed_nodes.is_empty(),
        "Command chain should not be empty"
    );
    assert!(
        command.parsed_nodes.len() == 1,
        "Command chain should have exactly one node"
    );
    let last_in_chain = command
        .parsed_nodes
        .last()
        .expect("No command in parse chain");
    assert!(
        last_in_chain.metadata.category == Some(CommandCategory::Disassemble),
        "Command category should be Disassemble"
    );
    let address = match last_in_chain.parsed_options.iter().find(|option| {
        option
            .metadata
            .aliases
            .iter()
            .any(|alias_arg| alias_arg.contains(&"address"))
    }) {
        Some(ParsedOption { value, metadata }) => {
            if value.is_empty() {
                return Err(anyhow::anyhow!(
                    "Option '{}' requires a value",
                    metadata.aliases.join(", ")
                ));
            }
            if !(value.starts_with("0x") || value.starts_with("0X")) {
                return Err(anyhow::anyhow!(
                    "Hex Address must start with '0x' or '0X': {}",
                    value
                ));
            }
            let address = usize::from_str_radix(&value[2..], 16)
                .map_err(|_| anyhow::anyhow!("Invalid hex address: {}", value))?;
            VirtAddress::new(address)
        }
        None => process.get_pc()?,
    };

    let number_of_instructions = match last_in_chain.parsed_options.iter().find(|option| {
        option
            .metadata
            .aliases
            .iter()
            .any(|alias_arg| alias_arg.contains(&"number"))
    }) {
        Some(ParsedOption { value, metadata }) => {
            if value.is_empty() {
                return Err(anyhow::anyhow!(
                    "Option '{}' requires a value",
                    metadata.aliases.join(", ")
                ));
            }
            value
                .parse::<usize>()
                .map_err(|_| anyhow::anyhow!("Invalid number of instructions: {}", value))?
        }
        None => 10, // Default to 10 instructions if not specified
    };
    print_disassembly(process, number_of_instructions, Some(address))
}
