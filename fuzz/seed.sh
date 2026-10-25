#!/usr/bin/env bash
# Copies built fixture binaries into the ELF-based fuzz corpora as seeds.
# Build them first with `cargo build --workspace`.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
for target in elf_parse dwarf_full; do
    mkdir -p "$root/fuzz/corpus/$target"
done
for name in dwarf_fixture overload_fixture no_debug_fixture step_test_fixture; do
    # Newest build output for each fixture.
    src="$(find "$root/target/debug/build" -type f -name "$name" -path '*/out/*' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
    [ -n "$src" ] || { echo "missing $name; run cargo build --workspace" >&2; continue; }
    for target in elf_parse dwarf_full; do
        cp "$src" "$root/fuzz/corpus/$target/seed_$name"
    done
done
cp "$root/target/debug/hello_sdb" "$root/fuzz/corpus/elf_parse/seed_hello_sdb" 2>/dev/null || true
