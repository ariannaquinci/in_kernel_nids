./detach_xdp_unload_modules.sh
cd modules
make load_tcp
cd ..
make OUTPUT=/tmp/xdp-output all
OUTPUT_DIR=/tmp/xdp-output ./attach_xdp.sh enp1s0 --monitor tcp --workload off

