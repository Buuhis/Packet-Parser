CC      := gcc-12
CFLAGS  := -O2 -Wall -Wextra -std=gnu11 -Isrc -Isig_encrypt/inc -I/usr/include/postgresql -I/usr/include/libnl3
LDFLAGS := -pthread -lpq -lnl-3 -lnl-genl-3 -Lsig_encrypt/lib -Wl,-rpath,/usr/local/lib -lscrypt -lcrypto

BIN := sd-wan

SRC := \
    src/main.c \
    src/kernel_sync.c \
    src/app_context.c \
    sig_encrypt/src/traffic_crypto.c \
    sig_encrypt/src/pqc_handshake.c \
    sig_encrypt/src/pqc_logger.c \
    sig_encrypt/src/pqc_ipc.c \
    $(wildcard src/cli/*.c) \
    $(wildcard src/config/*.c) \
    $(wildcard src/utils/*.c) \
    $(wildcard src/system/*.c)

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
	install -m 755 sig_encrypt/lib/libscrypt.so /usr/local/lib/libscrypt.so
	ldconfig
	@echo "Installed $(BIN), mwan_kmod.ko, and libscrypt.so globally"

install-service:
	install -m 644 systemd/sd-wan.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Service installed. You can now use: systemctl enable --now sd-wan"

clean:
	rm -f $(BIN) $(OBJ)
	$(MAKE) -C kernel clean

