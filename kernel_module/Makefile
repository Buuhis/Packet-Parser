CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=gnu11 -Isrc -I/usr/include/postgresql -I/usr/include/libnl3
LDFLAGS := -pthread -lpq -lnl-3 -lnl-genl-3

BIN := sep-wan

SRC := \
    src/main.c \
    src/kernel_sync.c \
    src/app_context.c \
    $(wildcard src/config/*.c) \
    $(wildcard src/proto/*.c) \
    $(wildcard src/system/*.c) \
    $(wildcard src/userio/*.c) \
    $(wildcard src/utils/*.c)

OBJ := $(SRC:.c=.o)

.PHONY: all clean install kernel-mod

all: $(BIN) kernel-mod

kernel-mod:
	$(MAKE) -C kernel

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	install -m 755 $(BIN) /usr/local/bin/
	mkdir -p /usr/local/lib/modules/
	install -m 644 kernel/mwan_kmod.ko /usr/local/lib/modules/
	@echo "Installed $(BIN) and mwan_kmod.ko globally"

install-service:
	install -m 644 systemd/sep-wan.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Service installed. You can now use: systemctl enable --now sep-wan"

clean:
	rm -f $(BIN) $(OBJ)
	$(MAKE) -C kernel clean

