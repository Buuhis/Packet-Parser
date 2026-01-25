CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=gnu11 -Isrc
LDFLAGS :=

BIN := mwanc

SRC := \
    src/main.c \
    src/app_context.c \
    src/config/config_parser.c \
    src/system/sysctl.c \
    src/system/routing.c \
    src/system/netdev.c \
    src/tc/tc_init.c \
    src/tc/tc_class.c \
    src/tc/tc_filter.c \
    src/tc/tc_ingress.c \
	src/tc/tc_egress.c \
	src/userio/afpkt.c \
    src/utils/logger.c

OBJ := $(SRC:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJ)

