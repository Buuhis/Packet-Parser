CC = gcc
CLANG = clang
AR = ar

# Thêm -I/usr/local/include, -Isig_encrypt/inc và -Ifailover/inc để nhận diện header mới
CFLAGS = -D_GNU_SOURCE -Iinc -Isig_encrypt/inc -Ifailover/inc -I/usr/local/include -Wall -O2 $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})

# Quan trọng: Thêm -L/usr/local/lib và -Lsig_encrypt/lib để Linker tìm thấy thư viện.
# Thêm -Wl,-rpath để chương trình tìm thấy file .so lúc chạy mà không cần ldconfig.
LDFLAGS = -L/usr/local/lib -Lsig_encrypt/lib -lxdp -lbpf -lpthread -lssl -lcrypto -lpq -Wl,-rpath,$(shell pwd)/sig_encrypt/lib

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin

APP_SRC = main.c src/core/main_diag.c src/core/interface.c src/core/forwarder.c src/core/wan_arp.c src/crypto/crypto_policy_utils.c src/crypto/crypto_dispatch.c src/crypto/packet_crypto.c src/crypto/crypto_layer2.c src/crypto/crypto_layer3.c src/crypto/crypto_layer4.c src/core/flow_table.c src/core/fragment.c sig_encrypt/src/traffic_crypto.c sig_encrypt/src/pqc_handshake.c sig_encrypt/src/pqc_l2_handshake.c sig_encrypt/src/pqc_ipc.c sig_encrypt/src/pqc_logger.c failover/src/cfm_diag.c
APP_OBJ = $(APP_SRC:.c=.o)
TARGET = $(BIN_DIR)/test_network-encryptor
DB_LIB_SRC = src/db/config.c src/db/db_config.c src/db/db_env.c src/db/db_runtime.c
DB_LIB_OBJ = $(DB_LIB_SRC:.c=.o)
DB_LIB = $(BIN_DIR)/libdb_loader.a
DB_TEST_SRC = src/db_loader_test.c src/core/main_diag.c sig_encrypt/src/traffic_crypto.c sig_encrypt/src/pqc_handshake.c sig_encrypt/src/pqc_l2_handshake.c sig_encrypt/src/pqc_logger.c
DB_TEST_OBJ = $(DB_TEST_SRC:.c=.o)
DB_TEST_TARGET = $(BIN_DIR)/db-loader-test

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

.PHONY: all clean run dirs

all: dirs $(BPF_OBJ) $(DB_LIB) $(TARGET) $(DB_TEST_TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

# Sửa lại thứ tự: File .o đứng trước LDFLAGS để Linker hoạt động chuẩn
$(DB_LIB): $(DB_LIB_OBJ)
	$(AR) rcs $@ $(DB_LIB_OBJ)

$(TARGET): $(APP_OBJ) $(DB_LIB)
	$(CC) -o $@ $(APP_OBJ) $(DB_LIB) $(LDFLAGS)

$(DB_TEST_TARGET): $(DB_TEST_OBJ) $(DB_LIB)
	$(CC) -o $@ $(DB_TEST_OBJ) $(DB_LIB) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Bổ sung -I/usr/local/include cho phần BPF để đồng bộ
bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I/usr/local/include -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o src/core/*.o src/crypto/*.o src/db/*.o *.o $(BPF_OBJ) sig_encrypt/src/*.o failover/src/*.o

run:
	sudo DB_URL="host=localhost user=postgres dbname=xdpdb" $(TARGET) -id 1
