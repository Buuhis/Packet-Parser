# UDP Load Balancer - Round Robin + Reorder
# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread

TARGET = udp_lb
SRCS = main.c multiple_thread.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c packet_queue.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Note: packet_queue.h is the header file (multiple_thread.h)
main.o: main.c packet_queue.h
	$(CC) $(CFLAGS) -c -o $@ $<

multiple_thread.o: multiple_thread.c packet_queue.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

# Example run (requires config file)
run: $(TARGET)
	sudo ./$(TARGET) config.txt
