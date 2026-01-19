# ==============================
# Toolchain
# ==============================
CC          := gcc
CLANG       := clang

# ==============================
# Directories
# ==============================
SRC_DIR     := src
BPF_DIR     := bpf
BUILD_DIR   := build

# ==============================
# Compiler flags
# ==============================
CFLAGS      := -O2 -Wall -Wextra -std=c11 -Isrc
LDFLAGS     :=
LIBS        := -lbpf

BPF_CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_x86

# ==============================
# Main application (mwanc)
# ==============================
BIN         := mwanc

SRC_MAIN := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/app_context.c \
	$(SRC_DIR)/config/config_parser.c \
	$(SRC_DIR)/system/sysctl.c \
	$(SRC_DIR)/system/routing.c \
	$(SRC_DIR)/tc/tc_init.c \
	$(SRC_DIR)/tc/tc_class.c \
	$(SRC_DIR)/tc/tc_filter.c \
	$(SRC_DIR)/tc/tc_cleanup.c \
	$(SRC_DIR)/utils/logger.c

OBJ_MAIN := $(SRC_MAIN:%.c=$(BUILD_DIR)/%.o)

# ==============================
# XDP / BPF
# ==============================
BPF_OBJ     := $(BPF_DIR)/xdp_wanopt_kern.o
BPF_SRC     := $(SRC_DIR)/xdp/xdp_wanopt_kern.c
BPF_HDR     := $(SRC_DIR)/xdp/xdp_wanopt_kern.h

# ==============================
# AF_XDP userspace capture tool (7A-1)
# ==============================
XSK_BIN     := xsk_capture

XSK_SRC := \
	$(SRC_DIR)/xsk/xsk_capture.c \
	$(SRC_DIR)/utils/logger.c

OBJ_XSK := $(XSK_SRC:%.c=$(BUILD_DIR)/%.o)

# ==============================
# Default target
# ==============================
.PHONY: all
all: dirs $(BIN) $(BPF_OBJ) $(XSK_BIN)

# ==============================
# Create build directories
# ==============================
.PHONY: dirs
dirs:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/src
	mkdir -p $(BUILD_DIR)/src/config
	mkdir -p $(BUILD_DIR)/src/system
	mkdir -p $(BUILD_DIR)/src/tc
	mkdir -p $(BUILD_DIR)/src/utils
	mkdir -p $(BUILD_DIR)/src/xsk
	mkdir -p $(BPF_DIR)

# ==============================
# Build main application
# ==============================
$(BIN): $(OBJ_MAIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ==============================
# Build AF_XDP userspace capture tool
# ==============================
$(XSK_BIN): $(OBJ_XSK)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# ==============================
# Compile C sources to objects
# ==============================
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# ==============================
# Build XDP BPF object
# ==============================
$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ==============================
# Clean
# ==============================
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BIN)
	rm -f $(XSK_BIN)
	rm -f $(BPF_DIR)/*.o

