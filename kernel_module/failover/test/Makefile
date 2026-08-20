CC ?= gcc
CPPFLAGS := -I../inc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=gnu11

BIN := failover_test
SRC := main.c ../src/bfd.c

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f $(BIN)
