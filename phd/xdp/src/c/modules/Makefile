obj-m += deferred_analysis.o
obj-m += netfilter_hook.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build solo deferred_analysis
deferred_analysis:
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis.ko

# Build solo netfilter_hook
netfilter_hook:
	$(MAKE) -C $(KDIR) M=$(PWD) netfilter_hook.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	insmod deferred_analysis.ko
	insmod netfilter_hook.ko

unload:
	rmmod netfilter_hook
	rmmod deferred_analysis
