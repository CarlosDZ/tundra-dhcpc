## Compilation

CC = gcc
VERSION = $(shell grep '^version=' metapkg | cut -d= -f2)

TUNDRA_IP_PATH ?= /usr/bin/tundra-ip
TUNDRA_BLUEICE_ARP_PATH ?= /usr/bin/tundra-blueice-arp
TUNDRA_DHCPC_TIME_SCALE ?= 1

TUNDRA_STD  = -std=c11
TUNDRA_DEFS = -D_GNU_SOURCE -DTUNDRA_DHCPC_VERSION=\"$(VERSION)\" \
              -DTUNDRA_IP_PATH=\"$(TUNDRA_IP_PATH)\" \
              -DTUNDRA_BLUEICE_ARP_PATH=\"$(TUNDRA_BLUEICE_ARP_PATH)\" \
              -DTUNDRA_DHCPC_TIME_SCALE=$(TUNDRA_DHCPC_TIME_SCALE)
TUNDRA_INC  = -Isrc -Isrc/net -Isrc/dhcp
TUNDRA_LIBS = -lseccomp

CFLAGS ?= -Wall -Wextra -O2

TARGET = tundra-dhcpc

BUILD = build
SRCS = $(wildcard src/*.c src/net/*.c src/dhcp/*.c)
HDRS = $(wildcard src/*.h src/net/*.h src/dhcp/*.h)
OBJS = $(SRCS:src/%.c=$(BUILD)/%.o)
DEPS = $(OBJS:.o=.d)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(TUNDRA_LIBS)

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
TEST_TOOLS = $(patsubst tests/tools/%.c,$(TEST_BUILD)/tools/%,$(wildcard tests/tools/*.c))
TEST_DEFS = -D_GNU_SOURCE -DTUNDRA_DHCPC_VERSION=\"$(VERSION)-test\" \
            -DTUNDRA_IP_PATH=\"$(CURDIR)/tests/tools/tip-fail.sh\" \
            -DTUNDRA_BLUEICE_ARP_PATH=\"$(CURDIR)/tests/tools/biarp-fake.sh\" \
            -DTUNDRA_DHCPC_TIME_SCALE=6

$(TEST_BIN): FORCE
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(TUNDRA_INC) $(TEST_DEFS) -o $@ $(SRCS) $(TUNDRA_LIBS)

$(TEST_BUILD)/tools/%: tests/tools/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) -D_GNU_SOURCE -o $@ $<

UNIT_FLAGS = -g -fsanitize=address,undefined -fno-omit-frame-pointer
UNIT_TESTS = $(patsubst tests/unit/%.c,$(TEST_BUILD)/unit/%,$(wildcard tests/unit/*.c))

$(TEST_BUILD)/unit/%: tests/unit/%.c tests/unit/test.h $(SRCS) $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(TUNDRA_STD) $(CFLAGS) $(UNIT_FLAGS) $(TUNDRA_INC) -Itests/unit \
		-D_GNU_SOURCE -DTUNDRA_DHCPC_TIME_SCALE=1 \
		-DTUNDRA_BLUEICE_ARP_PATH=\"/nonexistent\" -o $@ $<

check-unit: $(UNIT_TESTS)
	@rc=0; for t in $(UNIT_TESTS); do echo "# $$t"; $$t || rc=1; done; exit $$rc

check: check-unit $(TEST_BIN) $(TEST_TOOLS)
	@sh tests/net/run.sh

FORCE:

.PHONY: install uninstall clean check check-unit FORCE


## Installation

PREFIX ?= /usr
DESTDIR ?=

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)/LICENSE

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -rf $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)
