# SPDX-License-Identifier: GPL-2.0
include ../scripts/Makefile.include

bindir ?= /usr/bin

# This will work when dma is built in tools env. where srctree
# isn't set and when invoked from selftests build, where srctree
# is set to ".". building_out_of_srctree is undefined for in srctree
# builds
ifndef building_out_of_srctree
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
endif

# Do not use make's built-in rules
# (this improves performance and avoids hard-to-debug behaviour);
MAKEFLAGS += -r

override CFLAGS += -O2 -Wall -g -D_GNU_SOURCE -I$(OUTPUT)include

ALL_TARGETS := dma_map_benchmark dmabench
ALL_PROGRAMS := $(patsubst %,$(OUTPUT)%,$(ALL_TARGETS))

all: $(ALL_PROGRAMS)

export srctree OUTPUT CC LD CFLAGS
include $(srctree)/tools/build/Makefile.include

#
# We need the following to be outside of kernel tree
#
$(OUTPUT)include/linux/%.h: $(srctree)/include/uapi/linux/%.h
	mkdir -p $(OUTPUT)include/linux
	ln -sf $< $@

prepare: $(OUTPUT)include/linux/map_benchmark.h $(OUTPUT)include/linux/dmabench.h

$(ALL_PROGRAMS): $(OUTPUT)%: %.c | prepare
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

$(OUTPUT)dma_map_benchmark: $(OUTPUT)include/linux/map_benchmark.h
$(OUTPUT)dmabench: $(OUTPUT)include/linux/dmabench.h

clean:
	rm -f $(ALL_PROGRAMS)
	rm -rf $(OUTPUT)include
	find $(or $(OUTPUT),.) -name '*.o' -delete -o -name '\.*.d' -delete -o -name '\.*.cmd' -delete

install: $(ALL_PROGRAMS)
	install -d -m 755 $(DESTDIR)$(bindir);		\
	for program in $(ALL_PROGRAMS); do		\
		install $$program $(DESTDIR)$(bindir);	\
	done

.PHONY: all install clean prepare
