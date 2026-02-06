# Yggdrasil C library test
#
# Usage (from repo root):
#   ./contrib/lib/build                         # build shared lib first
#   make -C contrib/lib/test                    # compile test
#   make -C contrib/lib/test run                # compile and run
#
# Static linking:
#   ./contrib/lib/build -s                      # build static lib first
#   make -C contrib/lib/test STATIC=1           # compile test
#   make -C contrib/lib/test STATIC=1 run       # compile and run

UNAME_S := $(shell uname -s)
LIB_DIR ?= $(realpath ../../..)

CC ?= cc
CFLAGS = -Wall -Wextra -I$(LIB_DIR)

ifeq ($(UNAME_S),Darwin)
  SHARED_EXT = dylib
  RPATH = -Wl,-rpath,$(LIB_DIR)
endif
ifeq ($(UNAME_S),Linux)
  SHARED_EXT = so
  RPATH = -Wl,-rpath,'$$ORIGIN'/../../..
endif

ifdef STATIC
  LIBS = $(LIB_DIR)/libyggdrasil.a -lpthread -lm -lresolv -framework CoreFoundation -framework Security -framework Foundation
  ifeq ($(UNAME_S),Linux)
    LIBS = $(LIB_DIR)/libyggdrasil.a -lpthread -lm -lresolv
  endif
else
  LIBS = -L$(LIB_DIR) -lyggdrasil $(RPATH)
endif

test_yggdrasil: main.c
	$(CC) $(CFLAGS) -o $@ main.c $(LIBS)

test_iprwc: test_iprwc.c
	$(CC) $(CFLAGS) -o $@ test_iprwc.c $(LIBS)

run: test_yggdrasil
ifeq ($(UNAME_S),Darwin)
	DYLD_LIBRARY_PATH=$(LIB_DIR) ./test_yggdrasil
else
	LD_LIBRARY_PATH=$(LIB_DIR) ./test_yggdrasil
endif

run-iprwc: test_iprwc
ifeq ($(UNAME_S),Darwin)
	DYLD_LIBRARY_PATH=$(LIB_DIR) ./test_iprwc
else
	LD_LIBRARY_PATH=$(LIB_DIR) ./test_iprwc
endif

clean:
	rm -f test_yggdrasil test_iprwc

.PHONY: run run-iprwc clean
