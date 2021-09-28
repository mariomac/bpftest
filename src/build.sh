#!/bin/bash

set -euo pipefail

DUMMY_SRC=netdump.bcc.c
DUMMY_OBJ=netdump.elf
INCLUDE=


clang -O2 -emit-llvm -c ${DUMMY_SRC} ${INCLUDE} -o - | llc -march=bpf -filetype=obj -o ${DUMMY_OBJ}

