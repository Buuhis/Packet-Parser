CC = gcc
CFLAGS = -I../../inc -I../inc -I/usr/local/include -Wall -O2
LDFLAGS = -L/usr/local/lib -L../lib -lscrypt -lssl -lcrypto -lpthread -Wl,-rpath,$(shell pwd)/../lib

SRC = test_pqc_standalone.c ../src/traffic_crypto.c
INSPECTOR_SRC = pqc_packet_inspector.c ../src/traffic_crypto.c
PERF_SRC = test_pqc_perf.c ../src/traffic_crypto.c
GATEWAY_SRC = pqc_throughput_gateway.c ../src/traffic_crypto.c

TARGET = ../../bin/test_pqc_standalone
INSPECTOR_TARGET = ../../bin/pqc_packet_inspector
PERF_TARGET = ../../bin/test_pqc_perf
GATEWAY_TARGET = ../../bin/pqc_throughput_gateway

all: $(TARGET) $(INSPECTOR_TARGET) $(PERF_TARGET) $(GATEWAY_TARGET)

$(TARGET): $(SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

$(INSPECTOR_TARGET): $(INSPECTOR_SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $@ $(INSPECTOR_SRC) $(LDFLAGS)

$(PERF_TARGET): $(PERF_SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $@ $(PERF_SRC) $(LDFLAGS)

$(GATEWAY_TARGET): $(GATEWAY_SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $@ $(GATEWAY_SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(INSPECTOR_TARGET) $(PERF_TARGET) $(GATEWAY_TARGET)
