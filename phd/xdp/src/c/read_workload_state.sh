#!/usr/bin/env bash

set -euo pipefail

MAP_PATH="${1:-/sys/fs/bpf/xdp_nids/maps/workload_state_map}"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
else
    SUDO=(sudo)
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool non trovato nel PATH" >&2
    exit 1
fi

if [[ ! -e "$MAP_PATH" ]]; then
    echo "mappa non trovata: $MAP_PATH" >&2
    exit 1
fi

raw="$("${SUDO[@]}" bpftool map lookup pinned "$MAP_PATH" key hex 00 00 00 00)"

mapfile -t bytes < <(printf '%s\n' "$raw" | awk '
    /^value:/ {
        for (i = 2; i <= NF; i++)
            print $i
    }')

if [[ ${#bytes[@]} -lt 16 ]]; then
    echo "output inatteso da bpftool:" >&2
    printf '%s\n' "$raw" >&2
    exit 1
fi

le32() {
    local offset=$1
    echo $(( 16#${bytes[offset+0]} |
             (16#${bytes[offset+1]} << 8) |
             (16#${bytes[offset+2]} << 16) |
             (16#${bytes[offset+3]} << 24) ))
}

le64() {
    local offset=$1
    echo $(( 16#${bytes[offset+0]} |
             (16#${bytes[offset+1]} << 8) |
             (16#${bytes[offset+2]} << 16) |
             (16#${bytes[offset+3]} << 24) |
             (16#${bytes[offset+4]} << 32) |
             (16#${bytes[offset+5]} << 40) |
             (16#${bytes[offset+6]} << 48) |
             (16#${bytes[offset+7]} << 56) ))
}

workload_level="$(le32 0)"
deferred_budget="$(le32 4)"
last_update_ns="$(le64 8)"

case "$workload_level" in
    0) workload_label="LOW" ;;
    1) workload_label="MEDIUM" ;;
    2) workload_label="HIGH" ;;
    3) workload_label="CRITICAL" ;;
    *) workload_label="UNKNOWN" ;;
esac

printf 'map: %s\n' "$MAP_PATH"
printf 'workload_level: %s (%s)\n' "$workload_level" "$workload_label"
printf 'deferred_budget: %s\n' "$deferred_budget"
printf 'last_update_ns: %s\n' "$last_update_ns"
