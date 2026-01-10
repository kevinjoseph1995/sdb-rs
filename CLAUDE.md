# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**sdb-rs** is a learning-oriented re-implementation of the **sdb** debugger from Sy Brand's book [*Building a Debugger*](https://nostarch.com/building-a-debugger). It's a Linux x86-64 debugger built in Rust using ptrace.

## Build and Test Commands

### Building
```bash
# Build the debugger (default member)
cargo build

# Build in release mode
cargo build --release

# Build all workspace members
cargo build --workspace

# Build a specific tool
cargo build -p hello_sdb
cargo build -p libsdb
```

### Testing
```bash
# Run all tests
cargo test

# Run tests for a specific package
cargo test -p libsdb
cargo test -p sdb-rs

# Run a specific test by name
cargo test <test_name>

# Run tests in a specific file
cargo test --test process
```

### Running the Debugger
```bash
# Launch and debug a program
cargo run -- /path/to/executable

# Attach to running process by PID
cargo run -- --pid <pid>

# Pass arguments to the debugged program
cargo run -- /path/to/executable -- arg1 arg2
```

### Test Tools
The `tools/` directory contains test binaries used for validating debugger functionality:
- `hello_sdb` - Basic test program
- `reg_read`, `reg_write` - Register operation tests
- `memory_test` - Memory operation tests
- `anti_debugger` - Tests debugger detection mechanisms

## Architecture

### Workspace Structure

This is a Cargo workspace with two main crates:

1. **libsdb** (`libsdb/`) - Core debugger library
   - `process.rs` - Main `Process` struct and ptrace operations
   - `register_info.rs` - Register definitions and operations (x86-64)
   - `disassembler.rs` - Instruction disassembly using Zydis
   - `elf.rs` - Custom ELF file parsing (intentionally not using a crate)
   - `pipe_channel.rs` - IPC for capturing debuggee output

2. **sdb-rs** (`sdb-rs/`) - CLI debugger application
   - `main.rs` - Entry point, handles process launch/attach
   - `tui.rs` - Interactive REPL using rustyline with custom completion/hints
   - `command/mod.rs` - Command parsing with metadata-driven system
   - `command/*_command.rs` - Individual command implementations
   - `options.rs` - CLI argument parsing

### Process Control (libsdb/src/process.rs)

The `Process` struct is the central abstraction for debuggee control:

- **Creation**: `Process::launch()` forks and execs with ptrace enabled, `Process::attach()` attaches to existing PID
- **State Management**: Tracks `ProcessHandleState` (Running/Stopped/Exited/Terminated)
- **Wait Loop**: `wait_on_signal()` handles all ptrace events (breakpoints, syscalls, signals, exits)
- **Stop Reasons**: `StopReason` enum identifies why process stopped (breakpoint, syscall, signal, etc.)

Key capabilities:
- Software breakpoints (int3 instruction patching)
- Hardware breakpoints/watchpoints (debug registers DR0-DR3, DR7)
- Single-stepping (PTRACE_SINGLESTEP)
- Syscall catchpoints with configurable policy (None/All/Specific syscalls)
- Memory read/write via `process_vm_readv`/`process_vm_writev`
- Register read/write via `PTRACE_GETREGS`/`PTRACE_SETREGS`

### Command System (sdb-rs/src/command/)

The command system uses a metadata-driven approach:

- `COMMAND_METADATA_LIST` - Static tree of all commands with aliases, descriptions, subcommands
- `parse()` - Traverses command tree to parse input into `Command` struct
- `get_completions()` - Provides tab completion based on command tree
- Custom rustyline `Helper` provides hints showing available subcommands/options

Commands support:
- Aliases (e.g., "r", "reg", "register")
- Subcommands (e.g., "register read", "breakpoint set")
- Options with validation (e.g., "disassemble -a 0x1234 -n 20")

### Register Handling

- `RegisterId` enum defines all x86-64 registers (GPRs, segment, FP, debug)
- `RegisterInfo` provides metadata (name, type, format, dwarf number, offset in user struct)
- `Registers` struct wraps libc::user with accessors
- `RegisterValue` enum handles different formats (uint, float, vector)

### Breakpoint Types

- **Software breakpoints**: Replace instruction with 0xCC (int3), restore on hit
- **Hardware breakpoints**: Use debug registers, limited to 4 concurrent
- **Watchpoints**: Hardware data breakpoints (read/write/execute, 1/2/4/8 byte sizes)

Each has enable/disable, list, info commands.

### Syscall Catchpoints

- `SyscallCatchPolicyMode`: None, All, or Some(Vec<Sysno>)
- Implemented via PTRACE_SYSCALL which stops at entry and exit
- `expecting_syscall_exit` flag tracks whether next stop is entry or exit
- `TrapType::Syscall` distinguishes syscall stops from breakpoints

### ELF Parsing

Custom implementation in `elf.rs` (not using a crate per book's approach):
- Memory-mapped file access via `memmap` crate
- Manual struct layout matching ELF64 spec
- Parses headers, program headers, section headers
- Used for address space layout understanding

## Key Design Patterns

- **Error Handling**: Heavy use of `anyhow::Result` throughout
- **Process Lifecycle**: `terminate_on_end` flag controls whether to kill debuggee on debugger exit
- **State Synchronization**: Process state queried via `/proc/{pid}/stat` when needed
- **Signal Handling**: Ctrl-C sends SIGSTOP to debuggee instead of killing debugger
- **Output Capture**: Pipe redirection captures debuggee stdout for `dump_child_output` command

## Dependencies

- **nix** - ptrace, signals, process control
- **zydis** - x86-64 disassembly
- **syscalls** - syscall number definitions
- **rustyline** - REPL with history/completion
- **clap** - CLI argument parsing
- **memmap** - ELF file memory mapping
