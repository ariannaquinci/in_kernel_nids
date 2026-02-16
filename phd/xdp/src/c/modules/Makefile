obj-m += deferred_analysis.o
obj-m += netfilter_hook.o
obj-m += dw_nf_poll.o

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

# Build solo dw_nf_poll
dw_nf_poll:
	$(MAKE) -C $(KDIR) M=$(PWD) dw_nf_poll.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	insmod deferred_analysis.ko
	insmod netfilter_hook.ko
	insmod dw_nf_poll.ko

unload:
	rmmod dw_nf_poll
	rmmod netfilter_hook
	rmmod deferred_analysis
