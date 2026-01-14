# Multi-WAN Load Balancer
# Makefile
#
# Two versions:
#   1. udp_lb  - User-space packet forwarding (original)
#   2. tc_lb   - TC-based kernel forwarding (new, recommended)

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread

# Old version (user-space packet forwarding)
TARGET_OLD = udp_lb
SRCS_OLD = main.c multiple_thread.c
OBJS_OLD = $(SRCS_OLD:.c=.o)
HEADER_OLD = multiple_thread.h

# New version (TC-based, kernel forwarding)
TARGET_NEW = tc_lb
SRCS_NEW = main_tc.c tc_lb.c
OBJS_NEW = $(SRCS_NEW:.c=.o)
HEADER_NEW = tc_lb.h

.PHONY: all clean old new run run-tc help

# Default: build new TC-based version
all: $(TARGET_NEW)

# Build both versions
both: $(TARGET_OLD) $(TARGET_NEW)

# Old version (user-space)
old: $(TARGET_OLD)

$(TARGET_OLD): $(OBJS_OLD)
	$(CC) $(LDFLAGS) -o $@ $^

main.o: main.c $(HEADER_OLD)
	$(CC) $(CFLAGS) -c -o $@ $<

multiple_thread.o: multiple_thread.c $(HEADER_OLD)
	$(CC) $(CFLAGS) -c -o $@ $<

# New version (TC-based)
new: $(TARGET_NEW)

$(TARGET_NEW): $(OBJS_NEW)
	$(CC) $(LDFLAGS) -o $@ $^

main_tc.o: main_tc.c $(HEADER_NEW)
	$(CC) $(CFLAGS) -c -o $@ $<

tc_lb.o: tc_lb.c $(HEADER_NEW)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET_OLD) $(TARGET_NEW) $(OBJS_OLD) $(OBJS_NEW)

# Run old version
run: $(TARGET_OLD)
	sudo ./$(TARGET_OLD) config.txt

# Run new TC-based version
run-tc: $(TARGET_NEW)
	sudo ./$(TARGET_NEW) config.txt

help:
	@echo "Multi-WAN Load Balancer Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build TC-based version (default, recommended)"
	@echo "  new      - Build TC-based version (tc_lb)"
	@echo "  old      - Build user-space version (udp_lb)"
	@echo "  both     - Build both versions"
	@echo "  clean    - Remove all built files"
	@echo ""
	@echo "Run targets:"
	@echo "  run-tc   - Run TC-based version (requires sudo)"
	@echo "  run      - Run old user-space version (requires sudo)"
	@echo ""
	@echo "Config file format (config.txt):"
	@echo "  local eth0"
	@echo "  remote 192.168.2.0/24"
	@echo "  wan eth1 10.0.1.1 8.8.8.8"
	@echo "  wan eth2 10.0.2.1 8.8.8.8"
	@echo "  method roundrobin"
