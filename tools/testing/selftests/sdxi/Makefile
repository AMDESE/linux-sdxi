werror := -Werror
CFLAGS += -std=gnu17 -Og -Wall -Wextra $(werror) $(TOOLS_INCLUDES) $(KHDR_INCLUDES)
CPPFLAGS += -I../../../include/ -Ilib/

TEST_GEN_PROGS := context

include ../lib.mk

HOSTAR ?= ar

LIBDIR	:= $(OUTPUT)/lib
LIB	:= $(LIBDIR)/lib.a

all: $(LIB)

LIBDEPS := \
	Makefile \
	lib/descriptor.h \
	lib/fixture-context.h \
	lib/fixture-device.h \
	lib/lib.h
# Library
LIBSRC	:= context.c lib.c
LIBOBJ	:= $(LIBSRC:%.c=$(LIBDIR)/%.o)
EXTRA_CLEAN += $(LIBOBJ) $(LIB)

$(LIB): $(LIBOBJ)
	$(HOSTAR) rcs $@ $^

$(LIBDIR)/%.o: ./lib/%.c $(LIBDEPS)
	mkdir -p $(LIBDIR)
	$(CC) $< $(CFLAGS) $(CPPFLAGS) -o $@ -c

$(TEST_GEN_PROGS): $(LIB)
$(TEST_GEN_PROGS_EXTENDED): $(LIB)
