package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"

	bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
*/
import "C"

type IpEvent struct {
	SAddr    uint32
	DAddr    uint32
	Protocol uint8
	Length   uint16
}

const device = "eth0"

func main() {
	// TODO: use CO-RE to avoid recompiling each execution
	file, err := ioutil.ReadFile("./netdump.bcc.c")
	panicOnErr(err)

	m := bpf.NewModule(string(file), []string{})
	defer m.Close()

	fn, err := m.Load("inspect_network", C.BPF_PROG_TYPE_XDP, 1, 65536)
	panicOnErr(err)

	// TODO: select all devices with a deny list
	panicOnErr(m.AttachXDP(device, fn))
	defer func() {
		panicOnErr(m.RemoveXDP(device))
	}()

	table := bpf.NewTable(m.TableId("ip_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	panicOnErr(err)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		for data := range channel {
			var event IpEvent
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf("%s: %s --> %s (%d bytes)\n",
				protocol(event.Protocol), int2ip(event.SAddr), int2ip(event.DAddr), event.Length)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func protocol(enum uint8) string {
	switch enum {
	case 0:
		return "IP"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPIP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPV6"
	case 255:
		return "RAW"
	default:
		return strconv.Itoa(int(enum))
	}
}
