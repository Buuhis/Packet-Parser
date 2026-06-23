CC = gcc
CFLAGS = -D_GNU_SOURCE -I. -Iinc -I../inc -I../inc/core -I../inc/crypto -I../inc/db -I../include -Wall -O2 -mcmodel=medium $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -L../lib -Wl,-rpath,'$$ORIGIN/../../lib' -lxdp -lbpf -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt

TARGET = cfm_test

SRC = src/cfm_test.c src/cfm_diag.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
