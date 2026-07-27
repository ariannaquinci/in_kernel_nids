#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$ROOT_DIR/modules"

IFACE="${IFACE:-}"
IP="${IP:-}"
PORT="${PORT:-9009}"
DURATION="${DURATION:-15}"
DEFERRED_WORKER_COUNT="${DEFERRED_WORKER_COUNT:-1}"
HOT_STATES="${HOT_STATES:-}"
LISTENER_LOG="${LISTENER_LOG:-/tmp/udp_deferred_inline_listener.log}"
PYTHON="${PYTHON:-python3}"

usage() {
	cat <<USAGE
Usage: sudo ./measure_udp_deferred_vs_inline.sh [--iface IFACE] [--ip IP] [--port PORT] [--duration SECONDS]

Env:
  DEFERRED_WORKER_COUNT=N  Worker deferred UDP, default: 1
  HOT_STATES=0,1,...      Optional hot_state_array passed to deferred_analysis_udp

Run this on the receiver. Copy udp_latency_sender.py to the sender host and run it
when this script asks for each phase.
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--iface)
			IFACE="${2:?missing iface}"
			shift 2
			;;
		--ip)
			IP="${2:?missing ip}"
			shift 2
			;;
		--port)
			PORT="${2:?missing port}"
			shift 2
			;;
		--duration)
			DURATION="${2:?missing duration}"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "Run as root: sudo $0" >&2
	exit 1
fi

if [[ -z "$IFACE" ]]; then
	IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
fi

if [[ -z "$IP" ]]; then
	IP="$(ip -4 -o addr show dev "$IFACE" scope global | awk '{sub(/\/.*/, "", $4); print $4; exit}')"
fi

if [[ -z "$IFACE" || -z "$IP" ]]; then
	echo "Could not auto-detect IFACE/IP. Pass --iface and --ip." >&2
	exit 1
fi

cleanup_modules() {
	(
		cd "$MODULE_DIR"
		make unload >/dev/null 2>&1 || true
		rmmod netfilter_hook_udp >/dev/null 2>&1 || true
		rmmod netif_receive_udp_hook >/dev/null 2>&1 || true
		rmmod deferred_analysis_udp >/dev/null 2>&1 || true
	)
}

listener_pid=""
cleanup() {
	if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" >/dev/null 2>&1; then
		kill "$listener_pid" >/dev/null 2>&1 || true
		wait "$listener_pid" >/dev/null 2>&1 || true
	fi
	cleanup_modules
}
trap cleanup EXIT

start_listener() {
	rm -f "$LISTENER_LOG"
	"$PYTHON" -u - "$IP" "$PORT" >"$LISTENER_LOG" <<'PY' &
import socket
import sys
import time

ip = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((ip, port))
print(f"listener_ready ip={ip} port={port}", flush=True)

count = 0
total_service_ns = 0
max_service_ns = 0
while True:
    data, addr = sock.recvfrom(65535)
    t0 = time.perf_counter_ns()
    sock.sendto(data, addr)
    dt = time.perf_counter_ns() - t0
    count += 1
    total_service_ns += dt
    if dt > max_service_ns:
        max_service_ns = dt
    if count % 1000 == 0:
        avg = total_service_ns // count
        print(f"listener packets={count} echo_service_avg_ns={avg} echo_service_max_ns={max_service_ns}", flush=True)
PY
	listener_pid=$!

	for _ in $(seq 1 50); do
		if grep -q "listener_ready" "$LISTENER_LOG" 2>/dev/null; then
			return
		fi
		sleep 0.1
	done

	echo "Listener did not become ready. Log:" >&2
	cat "$LISTENER_LOG" >&2 || true
	exit 1
}

read_counter() {
	local name="$1"
	local path="/sys/module/deferred_analysis_udp/parameters/$name"
	if [[ -r "$path" ]]; then
		cat "$path"
	else
		echo 0
	fi
}

load_phase() {
	local mode="$1"
	local inline="$2"
	local make_args=(load_udp "INLINE_ANALYSIS=$inline" "SINGLE_WORKER=0" "DEFERRED_WORKER_COUNT=$DEFERRED_WORKER_COUNT")

	if [[ -n "$HOT_STATES" ]]; then
		make_args+=("HOT_STATES=$HOT_STATES")
	fi

	echo
	echo "=== Loading UDP mode: $mode ==="
	cleanup_modules
	(cd "$MODULE_DIR" && make "${make_args[@]}")
}

run_phase() {
	local mode="$1"
	local inline="$2"
	local sender_mode_arg="$3"

	load_phase "$mode" "$inline"

	local before_count before_total before_max
	before_count="$(read_counter st_schedule_delay_count)"
	before_total="$(read_counter st_schedule_delay_total_ns)"
	before_max="$(read_counter st_schedule_delay_max_ns)"

	echo
	echo "Receiver ready for $mode:"
	echo "  target: $IP:$PORT on $IFACE"
	echo "  sender command:"
	echo "    python3 udp_latency_sender.py --target $IP --port $PORT --mode $sender_mode_arg --duration $DURATION --count 100000000"
	echo
	echo "Start the sender now. Measuring for ${DURATION}s..."
	sleep "$DURATION"

	local after_count after_total after_max
	after_count="$(read_counter st_schedule_delay_count)"
	after_total="$(read_counter st_schedule_delay_total_ns)"
	after_max="$(read_counter st_schedule_delay_max_ns)"

	local delta_count=$((after_count - before_count))
	local delta_total=$((after_total - before_total))
	local avg=0
	if (( delta_count > 0 )); then
		avg=$((delta_total / delta_count))
	fi

	echo
	echo "Results $mode:"
	echo "  schedule_delay_count:    $delta_count"
	echo "  schedule_delay_total_ns: $delta_total"
	echo "  schedule_delay_avg_ns:   $avg"
	echo "  schedule_delay_max_ns:   $after_max"
	echo "  listener log tail:"
	tail -5 "$LISTENER_LOG" || true
}

echo "Building modules..."
(cd "$MODULE_DIR" && make)

start_listener
echo "UDP echo listener started: pid=$listener_pid log=$LISTENER_LOG"

run_phase "deferred" 0 "deferred"
run_phase "inline" 1 "inline"

echo
echo "Done. Sender-side RTT is printed by udp_latency_sender.py."
