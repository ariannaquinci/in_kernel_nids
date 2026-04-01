#!/bin/bash
# attach_xdp.sh

set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-.output}"
XDP_OBJ="$OUTPUT_DIR/xdp.bpf.o"
WORKLOAD_OBJ="$OUTPUT_DIR/workload_collector.bpf.o"
TC_OBJ="$OUTPUT_DIR/tc_ingress.bpf.o"
MONITOR_MODE="${MONITOR_MODE:-both}"

BPFFS_PATH="/sys/fs/bpf/xdp_nids"
IFACE="${XDP_IFACE:-}"
ENABLE_WORKLOAD_COLLECTOR="${ENABLE_WORKLOAD_COLLECTOR:-1}"
SHARED_WORKLOAD_MAP="$BPFFS_PATH/maps/workload_state_map"

usage() {
    cat <<'EOF'
Usage: ./attach_xdp.sh [IFACE] [--workload on|off] [--monitor udp|tcp|both]

Environment variables:
  OUTPUT_DIR=<dir>                 Build output directory (default: .output)
  XDP_IFACE=<iface>                Default interface if IFACE is omitted
  ENABLE_WORKLOAD_COLLECTOR=0|1    Enable or disable workload collector (default: 1)
  MONITOR_MODE=udp|tcp|both        XDP frontend selection (default: both)

Examples:
  ./attach_xdp.sh enp1s0
  ./attach_xdp.sh enp1s0 --workload off
  ./attach_xdp.sh enp1s0 --monitor tcp
  ENABLE_WORKLOAD_COLLECTOR=0 ./attach_xdp.sh enp1s0
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workload)
            [[ $# -ge 2 ]] || { echo "ERRORE: manca valore per --workload"; usage; exit 1; }
            case "$2" in
                on) ENABLE_WORKLOAD_COLLECTOR=1 ;;
                off) ENABLE_WORKLOAD_COLLECTOR=0 ;;
                *) echo "ERRORE: --workload accetta solo 'on' o 'off'"; usage; exit 1 ;;
            esac
            shift 2
            ;;
        --monitor)
            [[ $# -ge 2 ]] || { echo "ERROR: missing value for --monitor"; usage; exit 1; }
            case "$2" in
                udp|tcp|both) MONITOR_MODE="$2" ;;
                *) echo "ERROR: --monitor accepts only 'udp', 'tcp', or 'both'"; usage; exit 1 ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "$IFACE" ]]; then
                IFACE="$1"
                shift
            else
                echo "ERRORE: argomento inatteso '$1'"
                usage
                exit 1
            fi
            ;;
    esac
done

case "$MONITOR_MODE" in
    udp|both)
        XDP_OBJ="$OUTPUT_DIR/xdp.bpf.o"
        ;;
    tcp)
        XDP_OBJ="$OUTPUT_DIR/xdp_tcp.bpf.o"
        ;;
esac

if [[ -z "$IFACE" ]]; then
    for dev in /sys/class/net/*; do
        dev="${dev##*/}"
        if [[ "$dev" != "lo" ]]; then
            IFACE="$dev"
            break
        fi
    done
fi

# 1. Check files and interface
[[ ! -f "$XDP_OBJ" ]] && { echo "ERRORE: $XDP_OBJ mancante"; exit 1; }
if [[ "$ENABLE_WORKLOAD_COLLECTOR" == "1" && ! -f "$WORKLOAD_OBJ" ]]; then
    echo "ERRORE: $WORKLOAD_OBJ mancante"
    exit 1
fi
#[[ ! -f "$TC_OBJ"  ]] && { echo "ERRORE: $TC_OBJ mancante (compila tc_ingress.bpf.c)"; exit 1; }

[[ ! -d "/sys/class/net/$IFACE" ]] && {
    echo "Interfacce disponibili:"
    ip -c a | grep UP | awk '{print $2}' | tr -d :
    exit 1
}

echo "XDP OBJ: $XDP_OBJ"
echo "Monitor mode: $MONITOR_MODE"
if [[ "$ENABLE_WORKLOAD_COLLECTOR" == "1" ]]; then
    echo "Workload collector OBJ: $WORKLOAD_OBJ"
else
    echo "Workload collector: disabled"
fi
#echo "TC  OBJ: $TC_OBJ"
echo "IFACE:   $IFACE"

# 2. Setup BPFFS
sudo rm -rf "$BPFFS_PATH"
sudo mkdir -p "$BPFFS_PATH"/{progs,maps}

# 3. LOAD & PIN XDP
PROG_PIN="$BPFFS_PATH/progs/xdp_prog"

echo "Load & Pin XDP..."
if sudo bpftool prog load "$XDP_OBJ" "$PROG_PIN" type xdp pinmaps "$BPFFS_PATH/maps"; then
    echo "SUCCESS: Load OK (con mappe pinnate)"
else
    echo "WARNING: Fallback: Load senza pinmaps..."
    sudo bpftool prog load "$XDP_OBJ" "$PROG_PIN" type xdp
fi

if [[ "$ENABLE_WORKLOAD_COLLECTOR" == "1" ]]; then
    COLLECTOR_PIN_DIR="$BPFFS_PATH/progs/workload_collector"
    echo "Load & auto-attach workload collector..."
    [[ -e "$SHARED_WORKLOAD_MAP" ]] || {
        echo "FAIL: mappa condivisa non trovata: $SHARED_WORKLOAD_MAP"
        exit 1
    }
    sudo mkdir -p "$COLLECTOR_PIN_DIR"
    sudo bpftool prog loadall "$WORKLOAD_OBJ" "$COLLECTOR_PIN_DIR" type tracepoint \
        map name workload_state_map pinned "$SHARED_WORKLOAD_MAP" \
        autoattach
else
    echo "Skip workload collector load (tracking disabled)"
fi

# 4. ATTACH XDP
echo "Attach XDP su $IFACE..."
SUCCESS=0
for mode in xdpdrv xdp generic; do
    if sudo bpftool net attach "$mode" pinned "$PROG_PIN" dev "$IFACE" 2>/dev/null; then
        echo "SUCCESS: ATTACHED XDP: $mode mode"
        SUCCESS=1
        ATTACH_MODE=$mode
        break
    fi
done
[[ $SUCCESS -eq 0 ]] && { echo "FAIL: Attach XDP fallito"; exit 1; }

# 5. ATTACH TC ingress (meta -> mark)
echo "Attach TC ingress (meta->mark) su $IFACE..."

# clsact necessario
sudo tc qdisc add dev "$IFACE" clsact 2>/dev/null || true

# sostituisci (così è idempotente)
#sudo tc filter replace dev "$IFACE" ingress bpf da obj "$TC_OBJ" sec "tc"

echo "SUCCESS: TC ingress attached su $IFACE"

echo ""
echo "=== STATO XDP ==="
sudo bpftool net show dev "$IFACE"

echo ""
echo "=== STATO TC ingress ($IFACE) ==="
tc filter show dev "$IFACE" ingress || true

echo ""
echo "Logs (kfunc calls):"
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
