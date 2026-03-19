CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=gnu11 -Isrc -I/usr/include/postgresql
LDFLAGS := -pthread -lpq

BIN := sep-wan

SRC := \
    src/main.c \
    src/dataplane.c \
    src/app_context.c \
    $(wildcard src/config/*.c) \
    $(wildcard src/proto/*.c) \
    $(wildcard src/system/*.c) \
    $(wildcard src/userio/*.c) \
    $(wildcard src/utils/*.c) \
    $(wildcard src/tc/*.c)

OBJ := $(SRC:.c=.o)

.PHONY: all clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	install -m 755 $(BIN) /usr/local/bin/
	@echo "Installed $(BIN) to /usr/local/bin/ globally"

install-service:
	install -m 644 systemd/sep-wan.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Service installed. You can now use: systemctl enable --now sep-wan"

clean:
	rm -f $(BIN) $(OBJ)

