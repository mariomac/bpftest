#!/bin/sh

xdpdump -i ${DEVICE} -w - | tshark -r - -T ek