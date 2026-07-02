# Makefile for CA NIF shared libraries
# Builds:
#   priv/se_nif.dylib   — macOS Secure Enclave NIF
#   priv/tpm_nif.so     — Linux TPM 2.0 NIF
#
# The correct target is selected automatically by the OS.

UNAME_S := $(shell uname -s)

ERL_ROOT     ?= $(shell erl -noshell -eval 'io:format("~s",[code:root_dir()])' -s init stop)
ERL_INCLUDE  := $(ERL_ROOT)/usr/include
PRIV_DIR     := ../priv

CFLAGS_COMMON := -O2 -Wall -fPIC -I$(ERL_INCLUDE)

# ------------------------------------------------------------------ #
#  macOS — Secure Enclave NIF                                          #
# ------------------------------------------------------------------ #
ifeq ($(UNAME_S), Darwin)

MACOS_SDK    := $(shell xcrun --show-sdk-path 2>/dev/null)
MACOS_ARCH   := $(shell uname -m)

CFLAGS_SE    := $(CFLAGS_COMMON) \
                -isysroot $(MACOS_SDK) \
                -target $(MACOS_ARCH)-apple-macos11.0
LDFLAGS_SE   := -dynamiclib -undefined dynamic_lookup \
                -framework Security \
                -framework CoreFoundation \
                -framework LocalAuthentication \
                -framework Foundation

all: $(PRIV_DIR)/se_nif.dylib

$(PRIV_DIR)/se_nif.dylib: se_nif.c
	@mkdir -p $(PRIV_DIR)
	$(CC) $(CFLAGS_SE) $(LDFLAGS_SE) -o $@ $<
	@echo "Built $(PRIV_DIR)/se_nif.dylib"

clean:
	rm -f $(PRIV_DIR)/se_nif.dylib

endif

# ------------------------------------------------------------------ #
#  Linux — TPM 2.0 NIF                                                #
# ------------------------------------------------------------------ #
ifeq ($(UNAME_S), Linux)

TSS2_CFLAGS  := $(shell pkg-config --cflags tss2-esys tss2-mu tss2-rc 2>/dev/null)
TSS2_LIBS    := $(shell pkg-config --libs   tss2-esys tss2-mu tss2-rc 2>/dev/null)

CFLAGS_TPM   := $(CFLAGS_COMMON) $(TSS2_CFLAGS)
LDFLAGS_TPM  := -shared $(TSS2_LIBS)

all: $(PRIV_DIR)/tpm_nif.so

$(PRIV_DIR)/tpm_nif.so: tpm_nif.c
	@mkdir -p $(PRIV_DIR)
	$(CC) $(CFLAGS_TPM) $(LDFLAGS_TPM) -o $@ $<
	@echo "Built $(PRIV_DIR)/tpm_nif.so"

clean:
	rm -f $(PRIV_DIR)/tpm_nif.so

endif
