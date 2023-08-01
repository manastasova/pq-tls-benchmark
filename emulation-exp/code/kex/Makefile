ROOT=$(shell dirname $(shell pwd))
INSTALL_DIR=$(ROOT)/install

s_timer.o: s_timer.c
	$(CC) -g -Wall -Wextra -Werror -Wpedantic -I$(INSTALL_DIR)/include $< -L$(INSTALL_DIR)/lib -lcrypto -ls2n -ldl -lpthread -o $@
