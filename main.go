package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/songgao/water"
)

var ErrInvalidIPHeader = fmt.Errorf("failed to parse IP header")
var ErrNonIPv4 = fmt.Errorf("can't handle non-IPv4 packets")

func formatIPAddress(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr>>24, (addr>>16)&0xFF, (addr>>8)&0xFF, addr&0xFF)
}

type IP struct {
	Version, HeaderLength, TypeOfService, Flags, TimeToLive, Protocol uint8
	TotalLength, Identification, FragmentOffset, HeaderChecksum       uint16
	SourceAddress, DestinationAddress                                 uint32
}

func (ip *IP) Inspect() {
	fmt.Printf("IP version:      %d\n", ip.Version)
	fmt.Printf("Header length:   %d\n", ip.HeaderLength)
	fmt.Printf("Type of service: %d\n", ip.TypeOfService)
	fmt.Printf("Total length:    %d\n", ip.TotalLength)
	fmt.Printf("Identification:  %d\n", ip.Identification)
	fmt.Printf("Flags:           %b\n", ip.Flags)
	fmt.Printf("Fragment offset: %d\n", ip.FragmentOffset)
	fmt.Printf("TTL:             %d\n", ip.TimeToLive)
	fmt.Printf("Protocol:        %d\n", ip.Protocol)
	fmt.Printf("Header checksum: %d\n", ip.HeaderChecksum)
	fmt.Printf("Source IP:       %s\n", formatIPAddress(ip.SourceAddress))
	fmt.Printf("Dest IP:         %s\n", formatIPAddress(ip.DestinationAddress))
	fmt.Println("")
}

func parseIPHeader(raw []byte) (ip IP, err error) {
	/*
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Version|  IHL  |Type of Service|          Total Length         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |         Identification        |Flags|      Fragment Offset    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  Time to Live |    Protocol   |         Header Checksum       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                       Source Address                          |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Destination Address                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Options                    |    Padding    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	**/

	buf := bytes.NewBuffer(raw)

	ip.Version, err = buf.ReadByte()
	if err != nil {
		return
	}

	ip.HeaderLength = ip.Version & 0x0F
	ip.Version = ip.Version >> 4

	if ip.Version != 4 {
		return ip, ErrNonIPv4
	}

	ip.TypeOfService, err = buf.ReadByte()
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &ip.TotalLength)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &ip.Identification)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &ip.FragmentOffset)
	if err != nil {
		return
	}

	ip.Flags = uint8(ip.FragmentOffset >> 13)
	ip.FragmentOffset = ip.FragmentOffset & 0x1FFF

	ip.TimeToLive, err = buf.ReadByte()
	if err != nil {
		return
	}

	ip.Protocol, err = buf.ReadByte()
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &ip.HeaderChecksum)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &ip.SourceAddress)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &ip.DestinationAddress)
	if err != nil {
		return
	}

	return
}

func main() {
	config := water.Config{DeviceType: water.TUN}
	config.Name = "tun_tcp"

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1500)

	for {
		n, err := ifce.Read(buf)
		if err != nil {
			log.Fatal(err)
		}

		ip, err := parseIPHeader(buf[:n])
		if err == ErrNonIPv4 {
			continue
		}
		if err != nil {
			log.Fatal(err)
		}

		ip.Inspect()
	}
}
