SHELL=/bin/bash -o pipefail
DEST_DIR?=./src
SRC_DIR?=./src
LINUX_HEADERS=$(shell rpm -q kernel-devel --last | head -n 1 | awk -F'kernel-devel-' '{print "/usr/src/kernels/"$$2}' | cut -d " " -f 1)

btf:
	mkdir -p "$(DEST_DIR)"
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -c $(SRC_DIR)/netdump.bcc.c \
		-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/netdump.elf"
