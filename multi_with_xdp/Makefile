CC = gcc
CLANG = clang
CFLAGS = -D_GNU_SOURCE -Iinc -Wall -O2
LDFLAGS = -lbpf -lxdp -lpthread

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin

SRC = main.c src/config.c src/interface.c src/forwarder.c src/flow_table.c src/fragment.c src/pipeline.c
OBJ = $(SRC:.c=.o)
TARGET = $(BIN_DIR)/xdp_forwarder

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

.PHONY: all clean run dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o *.o $(BPF_OBJ)

run: main
	sudo $(TARGET) config1.cfg
