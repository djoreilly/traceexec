OUTPUT = ./output
LIBBPF = ./libbpf

LIBBPF_SRC = $(abspath $(LIBBPF)/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = clang

ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
GOARCH := $(ARCH)

ifeq ($(GOARCH), amd64)
        BPFARCH=x86
else ifeq ($(GOARCH), arm64)
        BPFARCH=arm64
else ifeq ($(GOARCH), ppc64le)
        BPFARCH=powerpc
else ifeq ($(GOARCH), s390x)
        BPFARCH=s390
endif

BPFTOOL = $(shell which bpftool || /bin/false)
BTFFILE = /sys/kernel/btf/vmlinux
DBGVMLINUX = /usr/lib/debug/boot/vmlinux-$(shell uname -r)
GIT = $(shell which git || /bin/false)
VMLINUXH = vmlinux.h

# libbpf

LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))

CFLAGS = -ggdb -gdwarf -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function
LDFLAGS =

BPF_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
BPF_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-ldflags=-s -w'

## program

.PHONY: $(PROGRAM)
.PHONY: $(PROGRAM).bpf.c

PROGRAM = main

all:
	$(MAKE) -C . $(PROGRAM)

# vmlinux header file

.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): $(OUTPUT)
ifeq ($(wildcard $(BPFTOOL)),)
	@echo "ERROR: could not find bpftool"
	@exit 1
endif
	@if [ -f $(DBGVMLINUX) ]; then \
		echo "INFO: found dbg kernel, generating $(VMLINUXH) from $(DBGVMLINUX)"; \
		$(BPFTOOL) btf dump file $(DBGVMLINUX) format c > $(VMLINUXH); \
	fi
	@if [ ! -f $(BTFFILE) ] && [ ! -f $(DBGVMLINUX) ]; then \
		echo "ERROR: kernel does not seem to support BTF"; \
		exit 1; \
	fi
	@if [ ! -f $(VMLINUXH) ]; then \
		echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
		$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); \
	fi

# static libbpf generation for the git submodule

.PHONY: libbpf
libbpf: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= install
	$(MAKE) -C $(LIBBPF_SRC) UAPIDIR=$(LIBBPF_DESTDIR) install_uapi_headers

$(LIBBPF_SRC):
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libbpf'"
	$(GIT) submodule update --init --recursive
endif

# output dir

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/libbpf:
	mkdir -p $(OUTPUT)/libbpf

## program bpf dependency

$(PROGRAM).bpf.o: $(PROGRAM).bpf.c | vmlinuxh
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(BPFARCH) -I. -I$(OUTPUT) -c $< -o tmp.bpf.o
	$(BPFTOOL) gen object $@ tmp.bpf.o
	rm tmp.bpf.o

## GO example

.PHONY: $(PROGRAM)

$(PROGRAM): libbpf | $(PROGRAM).bpf.o
	CC=$(CC) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
                go build \
                -tags netgo $(CGO_EXTLDFLAGS_STATIC) \
                -o $(PROGRAM) ./$(PROGRAM).go

.PHONE: run
run:
	sudo ./main

.PHONE: cat
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

## clean

.PHONY: clean
clean:
	$(MAKE) -C $(LIBBPF_SRC) clean
	rm -rf $(OUTPUT)
	rm -rf $(VMLINUXH)
	rm -rf $(PROGRAM)
	rm -rf $(PROGRAM).bpf.o $(PROGRAM).o
