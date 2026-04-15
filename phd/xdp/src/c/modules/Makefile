obj-m += deferred_analysis_udp.o
obj-m += netfilter_hook_udp.o
obj-m += deferred_analysis_tcp.o
obj-m += tcp_stream_hook.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
TEARDOWN := $(abspath $(PWD)/../detach_xdp_unload_modules.sh)
PATTERN_FILE := $(abspath $(PWD)/../algolib/patterns.txt)
PATTERN_HEADER := $(abspath $(PWD)/dw_ac_patterns_autogen.h)

all: prepare_patterns
	$(MAKE) -C $(KDIR) M=$(PWD) modules

prepare_patterns: $(PATTERN_HEADER)

$(PATTERN_HEADER): $(PATTERN_FILE)
	@{ \
		echo "/* Auto-generated from $(PATTERN_FILE). Do not edit. */"; \
		echo "#ifndef __DW_AC_PATTERNS_AUTOGEN_H__"; \
		echo "#define __DW_AC_PATTERNS_AUTOGEN_H__"; \
		echo "#define DW_AC_PATTERN_LABEL \"patterns.txt\""; \
		printf "#define DW_AC_PATTERN_COUNT "; \
		awk 'NF { count++ } END { print count + 0 }' $<; \
		printf "#define DW_AC_MIN_LEN "; \
		awk 'NF { len = length($$0); if (!seen || len < min) min = len; seen = 1 } END { print seen ? min : 0 }' $<; \
		printf "#define DW_AC_MAX_LEN "; \
		awk 'NF { len = length($$0); if (len > max) max = len } END { print max + 0 }' $<; \
		echo "static const char *const dw_ac_patterns[] = {"; \
		awk 'NF { gsub(/["\\\\]/, "\\\\&"); printf "\t\"%s\",\n", $$0 }' $<; \
		echo "};"; \
		echo "#endif"; \
	} > $@

# Build only the UDP deferred backend
deferred_analysis_udp: prepare_patterns
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_udp.ko

# Build the UDP hook after generating Module.symvers for deferred_analysis_udp
netfilter_hook_udp: prepare_patterns
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_udp.ko
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(PWD)/Module.symvers netfilter_hook_udp.ko

# Build the TCP deferred backend stub
deferred_analysis_tcp: prepare_patterns
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_tcp.ko

# Build the TCP stream hook stub
tcp_stream_hook: prepare_patterns
	$(MAKE) -C $(KDIR) M=$(PWD) deferred_analysis_tcp.ko
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(PWD)/Module.symvers tcp_stream_hook.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) $(PATTERN_HEADER)

load:
	insmod deferred_analysis_tcp.ko
	insmod tcp_stream_hook.ko
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
	rmmod tcp_stream_hook
	rmmod deferred_analysis_tcp
	rmmod netfilter_hook_udp
	rmmod deferred_analysis_udp
	
