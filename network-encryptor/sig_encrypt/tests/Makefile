CC = gcc
CFLAGS = -I../../inc -I../inc -I/usr/local/include -Wall -O2
LDFLAGS = -L/usr/local/lib -L../lib -lscrypt -lssl -lcrypto -lpthread -Wl,-rpath,$(shell pwd)/../lib

SRC = test_pqc_standalone.c ../src/traffic_crypto.c
TARGET = ../../bin/test_pqc_standalone

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
