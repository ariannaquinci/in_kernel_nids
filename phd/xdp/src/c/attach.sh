
# build BPF/XDP in output temporaneo
make OUTPUT=/tmp/xdp-output all

# carica XDP + metriche latenza/hook cost
sudo PRINT_LEVEL=2 OUTPUT_DIR=/tmp/xdp-output ./attach_latency_metrics.sh enp1s0
