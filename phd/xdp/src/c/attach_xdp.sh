#!/bin/bash
# attach_xdp.sh

set -euo pipefail

XDP_OBJ=".output/xdp.bpf.o"
TC_OBJ=".output/tc_ingress.bpf.o"

BPFFS_PATH="/sys/fs/bpf/xdp_nids"
IFACE="${1:-enp7s0}"
ATTACH_TC_ON_LO="${2:-0}"   # passa "1" come secondo argomento se vuoi anche su lo

# 1. Check file e interfaccia
[[ ! -f "$XDP_OBJ" ]] && { echo "ERRORE: $XDP_OBJ mancante"; exit 1; }
#[[ ! -f "$TC_OBJ"  ]] && { echo "ERRORE: $TC_OBJ mancante (compila tc_ingress.bpf.c)"; exit 1; }

[[ ! -d "/sys/class/net/$IFACE" ]] && {
    echo "Interfacce disponibili:"
    ip -c a | grep UP | awk '{print $2}' | tr -d :
    exit 1
}

echo "XDP OBJ: $XDP_OBJ"
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

# opzionale: se reinietti su lo e vuoi marcare anche quelli
if [[ "$ATTACH_TC_ON_LO" == "1" ]]; then
  echo "Attach TC ingress anche su lo (per pacchetti reiniettati)..."
  sudo tc qdisc add dev lo clsact 2>/dev/null || true
  #sudo tc filter replace dev lo ingress bpf da obj "$TC_OBJ" sec "tc"
  echo "SUCCESS: TC ingress attached su lo"
fi

echo ""
echo "=== STATO XDP ==="
sudo bpftool net show dev "$IFACE"

echo ""
echo "=== STATO TC ingress ($IFACE) ==="
tc filter show dev "$IFACE" ingress || true

if [[ "$ATTACH_TC_ON_LO" == "1" ]]; then
  echo ""
  echo "=== STATO TC ingress (lo) ==="
  tc filter show dev lo ingress || true
fi

echo ""
echo "Logs (kfunc calls):"
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
echo "Stats Kernel Module:"
echo "  cat /sys/kernel/debug/udp_defer/stats"
