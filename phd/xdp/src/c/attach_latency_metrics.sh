#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-.output}"
BPFFS_PATH="${BPFFS_PATH:-/sys/fs/bpf/xdp_nids}"
IFACE="${XDP_IFACE:-}"
PRINT_LEVEL="${PRINT_LEVEL:-0}"

XDP_OBJ="${XDP_OBJ:-$OUTPUT_DIR/xdp.bpf.o}"

debug() {
	if [[ "$PRINT_LEVEL" -ge 2 ]]; then
		printf '%s\n' "$*"
	fi
}

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: ./attach_latency_metrics.sh [IFACE]

Environment variables:
  OUTPUT_DIR=<dir>       Build output directory, default .output
  BPFFS_PATH=<path>      Pin root, default /sys/fs/bpf/xdp_nids
  XDP_IFACE=<iface>      Interface if IFACE argument is omitted
  XDP_OBJ=<file>         BPF object with XDP and kprobes, default $OUTPUT_DIR/xdp.bpf.o
  PRINT_LEVEL=0|1|2      0/1 quiet, 2 debug/status output, default 0

After a PCAP replay, read aggregate XDP-to-UDP-stack latency with:
  sudo bpftool map dump pinned /sys/fs/bpf/xdp_nids/maps/path_latency_stats_map

Pinned latency maps:
  path_latency_stats_map  Aggregate counters, path latency, and hook overhead
  xdp_ingress_ts_map      XDP timestamp keyed by UDP packet identity
  path_latency_samples_map Per-sample XDP-to-UDP-stack latency values
  latency_pkt_seq_map     Per-CPU packet ID stamper for reproducible keys
  xdp_timestamp_ns_map    Last XDP timestamp, useful as a liveness check

This metrics XDP program stamps IPv4 ID on UDP packets and fixes the IPv4
header checksum so repeated packets can be correlated reliably downstream.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

if [[ $# -gt 1 ]]; then
	usage
	exit 1
fi

if [[ $# -eq 1 ]]; then
	IFACE="$1"
fi

if [[ -z "$IFACE" ]]; then
	for dev in /sys/class/net/*; do
		dev="${dev##*/}"
		if [[ "$dev" != "lo" ]]; then
			IFACE="$dev"
			break
		fi
	done
fi

[[ "$PRINT_LEVEL" =~ ^[0-9]+$ ]] || die "PRINT_LEVEL must be numeric"

[[ -n "$IFACE" ]] || die "interface not found"
[[ -d "/sys/class/net/$IFACE" ]] || die "missing interface $IFACE"
[[ -f "$XDP_OBJ" ]] || die "missing $XDP_OBJ"

PROG_DIR="$BPFFS_PATH/progs"
MAP_DIR="$BPFFS_PATH/maps"
XDP_PIN="$PROG_DIR/xdp_prog"

STATS_MAP="$MAP_DIR/path_latency_stats_map"
INGRESS_TS_MAP="$MAP_DIR/xdp_ingress_ts_map"
LATENCY_SEQ_MAP="$MAP_DIR/latency_pkt_seq_map"
SAMPLES_MAP="$MAP_DIR/path_latency_samples_map"
LAST_XDP_TS_MAP="$MAP_DIR/xdp_timestamp_ns_map"
REQUIRED_MAPS=(
	"$STATS_MAP"
	"$INGRESS_TS_MAP"
	"$LATENCY_SEQ_MAP"
	"$SAMPLES_MAP"
	"$LAST_XDP_TS_MAP"
)

debug "Interface:       $IFACE"
debug "XDP object:      $XDP_OBJ"
debug "BPFFS path:      $BPFFS_PATH"

debug "Reset pin tree..."
for mode in xdpdrv xdpgeneric xdpoffload; do
	sudo bpftool net detach "$mode" dev "$IFACE" 2>/dev/null || true
done
sudo rm -rf "$BPFFS_PATH"
sudo mkdir -p "$PROG_DIR" "$MAP_DIR"

debug "Load all programs, pin shared maps, and autoattach UDP enqueue kprobe..."
sudo bpftool prog loadall "$XDP_OBJ" "$PROG_DIR" pinmaps "$MAP_DIR" autoattach

for map_path in "${REQUIRED_MAPS[@]}"; do
	[[ -e "$map_path" ]] || die "missing pinned map $map_path"
done
[[ -e "$XDP_PIN" ]] || die "missing pinned XDP program $XDP_PIN"

debug "Attach XDP on $IFACE..."
ATTACHED=0
ATTACH_MODE=""
for mode in xdpdrv xdpgeneric; do
	if sudo bpftool net attach "$mode" pinned "$XDP_PIN" dev "$IFACE" 2>/dev/null; then
		debug "Attached XDP mode: $mode"
		ATTACHED=1
		ATTACH_MODE="$mode"
		break
	fi
done

if [[ "$ATTACHED" -ne 1 ]]; then
	die "XDP attach failed"
fi

debug ""
debug "Ready. XDP mode: $ATTACH_MODE"
debug "Replay UDP traffic now, then read aggregate XDP-to-UDP-stack latency:"
debug "  sudo bpftool map dump pinned $STATS_MAP"
debug ""
debug "Pinned latency maps:"
for map_path in "${REQUIRED_MAPS[@]}"; do
	debug "  $map_path"
done
debug ""
debug "Useful counters in path_latency_stats_map:"
debug "  Path latency: samples, total_delta_ns, avg_delta_ns, min_delta_ns, max_delta_ns"
debug "  XDP hook cost: xdp_hook_samples, xdp_hook_total_ns, xdp_hook_avg_ns,"
debug "                 xdp_hook_min_ns, xdp_hook_max_ns"
debug "  RX hook cost:  rx_hook_samples, rx_hook_total_ns, rx_hook_avg_ns,"
debug "                 rx_hook_min_ns, rx_hook_max_ns"
debug "  Counters:      xdp_seen, udp_seen, xdp_parse_fail, udp_parse_fail, lookup_miss"
