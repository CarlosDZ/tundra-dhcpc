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


## Installation

PREFIX ?= /usr
DESTDIR ?=

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)/LICENSE

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -rf $(DESTDIR)$(PREFIX)/share/licenses/$(TARGET)

.PHONY: install uninstall clean
