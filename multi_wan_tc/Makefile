CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 -Isrc
LDFLAGS :=

BIN := mwanc
SRC := \
  src/main.c \
  src/app_context.c \
  src/config/config_parser.c \
  src/system/sysctl.c \
  src/system/routing.c \
  src/tc/tc_init.c \
  src/utils/logger.c

OBJ := $(SRC:.c=.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all clean
