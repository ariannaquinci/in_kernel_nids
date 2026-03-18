obj-m += deferred_analysis.o
obj-m += netfilter_hook.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
TEARDOWN := $(abspath $(PWD)/../detach_xdp_unload_modules.sh)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build solo deferred_analysis
deferred_analysis:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis.ko

# Build netfilter_hook after generating Module.symvers for deferred_analysis
netfilter_hook:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis.ko
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(PWD)/Module.symvers netfilter_hook.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	insmod deferred_analysis.ko
	insmod netfilter_hook.ko

unload:
	@if [ -x "$(TEARDOWN)" ]; then \
		"$(TEARDOWN)"; \
	else \
		echo "missing teardown script: $(TEARDOWN)" >&2; \
		exit 1; \
	fi

