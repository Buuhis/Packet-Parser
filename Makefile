# Compiler and flags configuration
CC = gcc                                    # C compiler (GNU GCC)
CFLAGS = -Wall -Iinc -Iutil/inc            # Compiler flags: warnings + include paths
LDFLAGS = -lpcap                            # Linker flags: link against libpcap

# Source files and object files
SRC = src/main.c src/packet_parser.c src/tcp_parser.c src/udp_parser.c src/dns_parser.c util/src/logger.c
OBJ = $(SRC:.c=.o)                         # Generate object file names from source files
BIN = packet_parser                         # Output binary name

all: $(BIN)

# Main build rule - link object files into executable
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) $(BIN)
