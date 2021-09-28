package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
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
	SPort    uint16
	DPort    uint16
}

const device = "eth0"
const xdpProgram = "inspect_network"
const mapName = "ip_events"

func main() {
	m := elf.NewModule("netdump.elf") //bpf.NewModule(string(file), []string{})
	defer m.Close()

	err := m.Load(map[string]elf.SectionParams{
		mapName: {
			PinPath: xdpProgram,
		},
	})
	panicOnErr(err)

	// TODO: select all devices with a deny list
	panicOnErr(m.AttachXDP(device, xdpProgram))
	defer func() {
		panicOnErr(m.RemoveXDP(device))
	}()

	channel := make(chan []byte)
	perfMap, err := elf.InitPerfMap(m, mapName, channel, nil)
	panicOnErr(err)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		ipEvents := m.Map(mapName)
		noId := 0
		for {
			var event IpEvent
			err := m.LookupElement(ipEvents, unsafe.Pointer(&noId), unsafe.Pointer(&event))
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf("%s: %s:%d --> %s:%d\n",
				protocol(event.Protocol),
				int2ip(event.SAddr), event.SPort,
				int2ip(event.DAddr), event.DPort)
		}
	}()

	perfMap.PollStart()
	<-sig
	perfMap.PollStop()
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
