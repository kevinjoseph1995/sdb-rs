#!/usr/bin/env bash
# Print the runtime virtual address of a symbol in a running process.
# Usage: symbol_vaddr.sh <pid|name> [symbol]   (symbol defaults to _start)

set -euo pipefail

target="${1:?usage: symbol_vaddr.sh <pid|name> [symbol]}"
symbol="${2:-_start}"

if [[ "$target" =~ ^[0-9]+$ ]]; then
    pid="$target"
else
    mapfile -t pids < <(pgrep -x "$target")
    case "${#pids[@]}" in
        0) echo "no process found matching: $target" >&2; exit 1 ;;
        1) pid="${pids[0]}" ;;
        *) echo "multiple processes match '$target': ${pids[*]} (pass a pid instead)" >&2; exit 1 ;;
    esac
fi

exe="/proc/${pid}/exe"
[[ -e "$exe" ]] || { echo "no such process: $pid" >&2; exit 1; }

binary="$(readlink -f "$exe")"

offset="$(nm -D "$binary" 2>/dev/null | awk -v s="$symbol" '$3 == s {print $1}')"
if [[ -z "$offset" ]]; then
    offset="$(nm "$binary" 2>/dev/null | awk -v s="$symbol" '$3 == s {print $1}')"
fi
[[ -n "$offset" ]] || { echo "symbol not found: $symbol" >&2; exit 1; }

elf_type="$(readelf -h "$binary" | awk -F': *' '/Type:/ {print $2}')"

if [[ "$elf_type" == *"DYN"* ]]; then
    # PIE: address is base-load-address + symbol offset.
    base="$(awk -v exe="$binary" '$2 ~ /^r/ && $6 == exe {print $1; exit}' "/proc/${pid}/maps" | cut -d- -f1)"
    [[ -n "$base" ]] || { echo "could not find load base for $binary in /proc/${pid}/maps" >&2; exit 1; }
    printf '0x%x\n' "$(( 0x${base} + 0x${offset} ))"
else
    # Non-PIE: the symbol's link-time address is already the runtime address.
    printf '0x%x\n' "0x${offset}"
fi
