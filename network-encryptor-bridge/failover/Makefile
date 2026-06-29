CC = gcc
CFLAGS = -D_GNU_SOURCE -I. -Iinc -Itest -Wall -O2 -mcmodel=medium
LDFLAGS = -lpthread

TARGET = cfm_test

SRC = test/cfm_test.c src/cfm_diag.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
