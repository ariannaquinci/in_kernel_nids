#!/bin/bash
# attach_xdp.sh

set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-.output}"
XDP_OBJ="$OUTPUT_DIR/xdp.bpf.o"
WORKLOAD_OBJ="$OUTPUT_DIR/workload_collector.bpf.o"
TC_OBJ="$OUTPUT_DIR/tc_ingress.bpf.o"

BPFFS_PATH="/sys/fs/bpf/xdp_nids"
IFACE="${1:-${XDP_IFACE:-}}"
SHARED_WORKLOAD_MAP="$BPFFS_PATH/maps/workload_state_map"

if [[ -z "$IFACE" ]]; then
    for dev in /sys/class/net/*; do
        dev="${dev##*/}"
        if [[ "$dev" != "lo" ]]; then
            IFACE="$dev"
            break
        fi
    done
fi

# 1. Check file e interfaccia
[[ ! -f "$XDP_OBJ" ]] && { echo "ERRORE: $XDP_OBJ mancante"; exit 1; }
[[ ! -f "$WORKLOAD_OBJ" ]] && { echo "ERRORE: $WORKLOAD_OBJ mancante"; exit 1; }
#[[ ! -f "$TC_OBJ"  ]] && { echo "ERRORE: $TC_OBJ mancante (compila tc_ingress.bpf.c)"; exit 1; }

[[ ! -d "/sys/class/net/$IFACE" ]] && {
    echo "Interfacce disponibili:"
    ip -c a | grep UP | awk '{print $2}' | tr -d :
    exit 1
}

echo "XDP OBJ: $XDP_OBJ"
echo "Workload collector OBJ: $WORKLOAD_OBJ"
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

COLLECTOR_PIN="$BPFFS_PATH/progs/workload_collector"
echo "Load & auto-attach workload collector..."
[[ -e "$SHARED_WORKLOAD_MAP" ]] || {
    echo "FAIL: mappa condivisa non trovata: $SHARED_WORKLOAD_MAP"
    exit 1
}
sudo bpftool prog load "$WORKLOAD_OBJ" "$COLLECTOR_PIN" type tracepoint \
    map name workload_state_map pinned "$SHARED_WORKLOAD_MAP" \
    autoattach

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
echo "Stats Kernel Module:"
echo "  cat /sys/kernel/debug/udp_defer/stats"
