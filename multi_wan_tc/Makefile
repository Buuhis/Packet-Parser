CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=gnu11 -Isrc -I/usr/include/postgresql
LDFLAGS := -pthread -lpq

BIN := mwanc

SRC := \
    src/main.c \
    src/app_context.c \
    $(wildcard src/config/*.c) \
    $(wildcard src/proto/*.c) \
    $(wildcard src/system/*.c) \
    $(wildcard src/userio/*.c) \
    $(wildcard src/utils/*.c)

OBJ := $(SRC:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJ)

