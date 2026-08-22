CC      := gcc-12
CFLAGS  := -O2 -Wall -Wextra -std=gnu11 -Isrc -Isig_encrypt/inc -I/usr/include/postgresql -I/usr/include/libnl3
# Resolve libscrypt.so relative to the installed daemon instead of a development
# path.  The package installs it in /usr/lib/sd-wan.
LDFLAGS := -pthread -lpq -lnl-3 -lnl-genl-3 -Lsig_encrypt/lib -Wl,--disable-new-dtags,-rpath,'$$ORIGIN/../lib/sd-wan' -lscrypt -lcrypto

BIN := sd-wan

SRC := \
    src/main.c \
    src/kernel_sync.c \
    src/app_context.c \
    sig_encrypt/src/traffic_crypto.c \
    sig_encrypt/src/pqc_handshake.c \
    sig_encrypt/src/pqc_logger.c \
    sig_encrypt/src/pqc_vault.c \
    $(wildcard src/cli/*.c) \
    $(wildcard src/config/*.c) \
    $(wildcard src/utils/*.c) \
    $(wildcard src/system/*.c)

OBJ := $(SRC:.c=.o)

.PHONY: all clean install kernel-mod package

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
	mkdir -p /usr/local/lib/sd-wan/
	install -m 755 sig_encrypt/lib/libscrypt.so /usr/local/lib/sd-wan/libscrypt.so
	ldconfig
	@echo "Installed $(BIN) in /usr/local/bin/, mwan_kmod.ko, and libscrypt.so"

install-service:
	install -m 644 systemd/sd-wan.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Service installed. You can now use: systemctl enable --now sd-wan"

# Binary-only Debian package for the current kernel and architecture.
# Override VERSION when preparing a release, e.g. make package VERSION=1.2.0.
package:
	./packaging/build-deb.sh $(if $(VERSION),--version $(VERSION),)

clean:
	rm -f $(BIN) $(OBJ)
	$(MAKE) -C kernel clean
	rm -rf dist lib
