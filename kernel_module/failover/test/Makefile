CC ?= gcc
CPPFLAGS := -I../inc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=gnu11

BIN := failover_test
MULTI_BIN := multi_session_test
SRC := main.c ../src/bfd.c
MULTI_SRC := multi_session_test.c ../src/bfd.c

.PHONY: all check clean

all: $(BIN) $(MULTI_BIN)

$(BIN): $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC)

$(MULTI_BIN): $(MULTI_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(MULTI_SRC)

check: $(MULTI_BIN)
	./$(MULTI_BIN)

clean:
	rm -f $(BIN) $(MULTI_BIN)
