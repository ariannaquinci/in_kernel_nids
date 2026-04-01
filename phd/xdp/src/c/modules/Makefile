obj-m += deferred_analysis_udp.o
obj-m += netfilter_hook_udp.o
obj-m += deferred_analysis_tcp.o
obj-m += tcp_stream_hook.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
TEARDOWN := $(abspath $(PWD)/../detach_xdp_unload_modules.sh)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build only the UDP deferred backend
deferred_analysis_udp:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_udp.ko

# Build the UDP hook after generating Module.symvers for deferred_analysis_udp
netfilter_hook_udp:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_udp.ko
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(PWD)/Module.symvers netfilter_hook_udp.ko

# Build the TCP deferred backend stub
deferred_analysis_tcp:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_tcp.ko

# Build the TCP stream hook stub
tcp_stream_hook:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_tcp.ko
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(PWD)/Module.symvers tcp_stream_hook.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	insmod deferred_analysis_udp.ko
	insmod netfilter_hook_udp.ko

load_tcp:
	insmod deferred_analysis_tcp.ko
	insmod tcp_stream_hook.ko

load_all:
	insmod deferred_analysis_udp.ko
	insmod netfilter_hook_udp.ko
	insmod deferred_analysis_tcp.ko
	insmod tcp_stream_hook.ko

unload:
	@if [ -x "$(TEARDOWN)" ]; then \
		"$(TEARDOWN)"; \
	else \
		echo "missing teardown script: $(TEARDOWN)" >&2; \
		exit 1; \
	fi
