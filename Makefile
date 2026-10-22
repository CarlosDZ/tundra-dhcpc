## Compilation

CC = gcc
VERSION = $(shell grep '^version=' metapkg | cut -d= -f2)

TUNDRA_IP_PATH ?= /usr/bin/tundra-ip
TUNDRA_DHCPC_TIME_SCALE ?= 1

TUNDRA_STD  = -std=c11
TUNDRA_DEFS = -D_GNU_SOURCE -DTUNDRA_DHCPC_VERSION=\"$(VERSION)\" \
              -DTUNDRA_IP_PATH=\"$(TUNDRA_IP_PATH)\" \
              -DTUNDRA_DHCPC_TIME_SCALE=$(TUNDRA_DHCPC_TIME_SCALE)
TUNDRA_INC  = -Isrc -Isrc/net -Isrc/dhcp

CFLAGS ?= -Wall -Wextra -O2

TARGET = tundra-dhcpc

BUILD = build
SRCS = $(wildcard src/*.c src/net/*.c src/dhcp/*.c)
HDRS = $(wildcard src/*.h src/net/*.h src/dhcp/*.h)
OBJS = $(SRCS:src/%.c=$(BUILD)/%.o)
DEPS = $(OBJS:.o=.d)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CPPFLAGS) $(CFLAGS) $(TUNDRA_INC) $(TUNDRA_DEFS) -MMD -MP -c $< -o $@

-include $(DEPS)

$(OBJS): Makefile metapkg

clean:
	rm -rf $(BUILD) $(TARGET)

## Tests

TEST_BUILD = $(BUILD)/test
TEST_BIN = $(TEST_BUILD)/tundra-dhcpc
TEST_TOOLS = $(TEST_BUILD)/tools/arpsend $(TEST_BUILD)/tools/arpresp
TEST_DEFS = -D_GNU_SOURCE -DTUNDRA_DHCPC_VERSION=\"$(VERSION)-test\" \
            -DTUNDRA_IP_PATH=\"$(CURDIR)/tests/tools/tip-fail.sh\" \
            -DTUNDRA_DHCPC_TIME_SCALE=6

$(TEST_BIN): $(SRCS) $(HDRS) Makefile metapkg
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(TUNDRA_INC) $(TEST_DEFS) -o $@ $(SRCS)

$(TEST_BUILD)/tools/%: tests/tools/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) -D_GNU_SOURCE -o $@ $<

UNIT_FLAGS = -g -fsanitize=address,undefined -fno-omit-frame-pointer
UNIT_DEFS = -D_GNU_SOURCE -Itests/unit
UNIT_TESTS = $(TEST_BUILD)/unit/dhcp $(TEST_BUILD)/unit/lease \
             $(TEST_BUILD)/unit/checksum

$(TEST_BUILD)/unit/dhcp: tests/unit/dhcp.c src/dhcp/dhcp.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(UNIT_FLAGS) $(TUNDRA_INC) $(UNIT_DEFS) \
		-o $@ tests/unit/dhcp.c src/dhcp/dhcp.c

$(TEST_BUILD)/unit/lease: tests/unit/lease.c src/dhcp/lease.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(UNIT_FLAGS) $(TUNDRA_INC) $(UNIT_DEFS) \
		-o $@ tests/unit/lease.c src/dhcp/lease.c

$(TEST_BUILD)/unit/checksum: tests/unit/checksum.c src/net/rawsock.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(UNIT_FLAGS) $(TUNDRA_INC) $(UNIT_DEFS) \
		-o $@ tests/unit/checksum.c

check-unit: $(UNIT_TESTS)
	@rc=0; for t in $(UNIT_TESTS); do echo "# $$t"; $$t || rc=1; done; exit $$rc

check: check-unit $(TEST_BIN) $(TEST_TOOLS)
	@sh tests/net/run.sh

## Installation

PREFIX ?= /usr
DESTDIR ?=

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)/LICENSE

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -rf $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)

.PHONY: install uninstall clean check check-unit
