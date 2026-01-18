CC = clang
KVER = $(shell uname -r)
KBUILD = /lib/modules/$(KVER)/build

INCLUDES = -I/usr/include \
           -I/usr/include/x86_64-linux-gnu \
           -I/usr/include/bpf \
           -I$(KBUILD)/include \
           -I$(KBUILD)/include/uapi

CFLAGS = -O2 -g -target bpf $(INCLUDES) -Wall

SRC = xdp_block.c
TARGET = xdp_block.o

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)
