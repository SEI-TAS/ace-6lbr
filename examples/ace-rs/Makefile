DEFINES+=PROJECT_CONF_H=\"project-conf.h\"
CONTIKI_PROJECT = ace-rs

ACE_RS?=.
CONTIKI = $(ACE_RS)/../..

# Add Erbium
APPS += er-coap rest-engine

# Add TinyDTLS
APPS += tinydtls
CFLAGS += -DWITH_TINYDTLS=1
PROJECTDIRS += $(CONTIKI)/apps/tinydtls/aes $(CONTIKI)/apps/tinydtls/sha2 $(CONTIKI)/apps/tinydtls/ecc

all: $(CONTIKI_PROJECT)

# Ensure the TCP/IP stack is included.
CONTIKI_WITH_IPV6 = 1
#CONTIKI_WITH_RIME = 1

include $(CONTIKI)/Makefile.include
