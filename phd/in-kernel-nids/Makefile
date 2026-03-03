# Nome del modulo (my_module.ko)
obj-m += defer_packet_inspection.o

# Percorso ai sorgenti del kernel in uso
KDIR := /lib/modules/$(shell uname -r)/build

# Directory corrente
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
load-all:
	insmod defer_packet_inspection.ko
unload-all:
	rmmod defer_packet_inspection

