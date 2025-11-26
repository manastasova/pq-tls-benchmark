ROOT=$(shell dirname $(shell pwd))
INSTALL_DIR=$(ROOT)/install
S2N_BIN=$(ROOT)/s2n-tls/bin

CC=gcc
CFLAGS=-std=gnu99 -Wall -D_POSIX_C_SOURCE=200809L -I$(ROOT)/s2n-tls -I$(S2N_BIN) -I$(INSTALL_DIR)/include
LDFLAGS=-L$(INSTALL_DIR)/lib
LIBS=$(INSTALL_DIR)/lib/libs2n.a $(INSTALL_DIR)/lib/libcrypto.a -lpthread -ldl -lrt -lm

.PHONY: all clean

all: s_timer.o s2nd

s_timer.o: s_timer.c
	$(CC) -g -Wall -Wextra -Wpedantic -I$(INSTALL_DIR)/include $< $(INSTALL_DIR)/lib/libs2n.a $(INSTALL_DIR)/lib/libcrypto.a -o $@

s2nd: s2nd.c $(S2N_BIN)/echo.c $(S2N_BIN)/https.c $(S2N_BIN)/common.c $(S2N_BIN)/common.h
	$(CC) $(CFLAGS) s2nd.c $(S2N_BIN)/echo.c $(S2N_BIN)/https.c $(S2N_BIN)/common.c -o s2nd $(LDFLAGS) $(LIBS)
	@echo "✓ s2nd compiled successfully!"

clean:
	rm -f s_timer.o s2nd
