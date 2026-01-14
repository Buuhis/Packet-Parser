# UDP Load Balancer - Simple Round Robin
# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread

TARGET = udp_lb
SRCS = main.c multiple_thread.c
OBJS = $(SRCS:.c=.o)
HEADER = multiple_thread.h

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

# Example run (requires config file)
run: $(TARGET)
	sudo ./$(TARGET) config.txt
