DEFINES+=PROJECT_CONF_H=\"project-conf.h\"
CONTIKI_PROJECT = ace-rs

ACE_RS?=.
CONTIKI = $(ACE_RS)/../..

APPS += er-coap rest-engine
APPS += tinydtls
CFLAGS += -DWITH_TINYDTLS=1

PROJECTDIRS += $(CONTIKI)/apps/tinydtls/aes $(CONTIKI)/apps/tinydtls/sha2 $(CONTIKI)/apps/tinydtls/ecc

MODULES += core/net/ip

all: $(CONTIKI_PROJECT)

CONTIKI = ../..
CONTIKI_WITH_RIME = 1
include $(CONTIKI)/Makefile.include
