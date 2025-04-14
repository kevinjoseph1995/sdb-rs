/////////////////////////////////
use clap::Parser;
use std::path::PathBuf;
/////////////////////////////////

#[derive(Parser, Debug)]
pub struct Options {
    /// The PID of the process to attach to. This is mutually exclusive with the executable option.
    /// If both are provided, the executable option will be ignored.
    #[arg(short = 'p', long = "pid", required_unless_present = "executable")]
    pub pid: Option<i32>,

    /// The path to the executable to debug
    #[arg(required_unless_present = "pid")]
    pub executable: Option<PathBuf>,

    /// The arguments to pass to the executable being launched. Ignored if the PID is provided.
    #[arg(last = true)]
    pub program_args: Option<String>,
}
