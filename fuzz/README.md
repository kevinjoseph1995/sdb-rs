# Fuzzing

This crate holds cargo-fuzz targets for the byte and text parsers. It needs a nightly toolchain, so use the dedicated shell:

```
nix develop .#fuzz
cargo build --workspace
fuzz/seed.sh
cargo fuzz run <target> -- -max_total_time=60
```

`fuzz/seed.sh` copies the built fixture binaries into the `elf_parse` and `dwarf_full` corpora. Run it once so the fuzzer starts from valid ELF and DWARF input.

Targets: `cursor_ops`, `dwarf_abbrev`, `dwarf_compile_units`, `dwarf_full`, `elf_parse`, `register_value_parse`.
Crashing inputs land in `fuzz/artifacts/<target>/`. Replay one with `cargo fuzz run <target> <file>`.
