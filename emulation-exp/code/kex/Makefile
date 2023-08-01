ROOT=$(shell dirname $(shell pwd))
OPENSSL_DIR=$(ROOT)/install

OPENSSL_INCLUDE=$(OPENSSL_DIR)/include

OQS_INCLUDE=$(OPENSSL_DIR)/oqs/include
AWSLC_LIB=$(OPENSSL_DIR)/lib64

s_timer.o: s_timer.c
	$(CC) -g -Wall -Wextra -Werror -Wpedantic -I$(OPENSSL_INCLUDE) -I$(OQS_INCLUDE) $< -L$(OPENSSL_DIR) -L$(OQS_LIB) -lssl -lcrypto -ldl -lpthread -loqs -o $@
	#$(CC) -g -Wall -Wextra -Werror -Wpedantic -I$(OPENSSL_INCLUDE) -I$(OQS_INCLUDE) $< -L$(OPENSSL_DIR) -L$(OQS_LIB) -lssl -lcrypto -ldl -lpthread -loqs -o $@
