ROOT=$(shell dirname $(shell pwd))
INSTALL_DIR=$(ROOT)/install

s_timer.o: s_timer.c
	$(CC) -g -Wall -Wextra -Werror -Wpedantic -I$(INSTALL_DIR)/include $< $(INSTALL_DIR)/lib/libs2n.a $(INSTALL_DIR)/lib/libcrypto.a -o $@
