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

raw_json="$("${SUDO[@]}" bpftool -j map lookup pinned "$MAP_PATH" key hex 00 00 00 00)"

read_json_field() {
    local field=$1
    printf '%s\n' "$raw_json" | sed -n "s/.*\"$field\":[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -n1
}

workload_level="$(read_json_field workload_level)"
deferred_budget="$(read_json_field deferred_budget)"
last_update_ns="$(read_json_field last_update_ns)"
cpu_busy_pct="$(read_json_field cpu_busy_pct)"
net_rx_softirq_pct="$(read_json_field net_rx_softirq_pct)"
avg_wakeup_latency_us="$(read_json_field avg_wakeup_latency_us)"

if [[ -z "$workload_level" || -z "$deferred_budget" || -z "$last_update_ns" ]]; then
    echo "output inatteso da bpftool:" >&2
    printf '%s\n' "$raw_json" >&2
    exit 1
fi

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
printf 'cpu_busy_pct: %s\n' "$cpu_busy_pct"
printf 'net_rx_softirq_pct: %s\n' "$net_rx_softirq_pct"
printf 'avg_wakeup_latency_us: %s\n' "$avg_wakeup_latency_us"
