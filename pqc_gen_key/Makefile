CC = gcc
CFLAGS = -D_GNU_SOURCE -Iinc -Wall -O2
LDFLAGS = -Llib -Wl,-rpath,$(PWD)/lib -Wl,-rpath,/usr/local/lib/pqc -lscrypt -lssl -lcrypto -lpthread

SRCS = main.c src/traffic_crypto.c src/pqc_vault.c
OBJS = $(SRCS:.c=.o)
TARGET = bin/pqc

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p bin
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	@mkdir -p /usr/local/bin /usr/local/lib/pqc
	install -m 755 $(TARGET) /usr/local/bin/pqc
	install -m 755 lib/libscrypt.so /usr/local/lib/pqc/libscrypt.so

clean:
	rm -rf bin src/*.o *.o
