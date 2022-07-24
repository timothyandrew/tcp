package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
	fmt.Printf("----- IP Header -----\n")
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
}

type TCP struct {
	DataOffset, Reserved, ControlBits                            uint8
	SourcePort, DestinationPort, Window, Checksum, UrgentPointer uint16
	SequenceNumber, AcknowledgmentNumber                         uint32
}

func (tcp *TCP) Inspect() {
	controlBitsSet := []string{}
	if tcp.ControlBits&0x1 > 0 {
		controlBitsSet = append(controlBitsSet, "FIN")
	}
	if tcp.ControlBits&0x2 > 0 {
		controlBitsSet = append(controlBitsSet, "SYN")
	}
	if tcp.ControlBits&0x4 > 0 {
		controlBitsSet = append(controlBitsSet, "RST")
	}
	if tcp.ControlBits&0x8 > 0 {
		controlBitsSet = append(controlBitsSet, "PSH")
	}
	if tcp.ControlBits&0x10 > 0 {
		controlBitsSet = append(controlBitsSet, "ACK")
	}
	if tcp.ControlBits&0x20 > 0 {
		controlBitsSet = append(controlBitsSet, "URG")
	}

	fmt.Printf("----- TCP Header -----\n")
	fmt.Printf("Source port:            %d\n", tcp.SourcePort)
	fmt.Printf("Destination port:       %d\n", tcp.DestinationPort)
	fmt.Printf("Sequence number:        %d\n", tcp.SequenceNumber)
	fmt.Printf("Acknowledgement number: %d\n", tcp.AcknowledgmentNumber)
	fmt.Printf("Data offset:            %d\n", tcp.DataOffset)
	fmt.Printf("Reserved:               %d\n", tcp.Reserved)
	fmt.Printf("Control bits:           %s\n", controlBitsSet)
	fmt.Printf("Window:                 %d\n", tcp.Window)
	fmt.Printf("Checksum:               %d\n", tcp.Checksum)
	fmt.Printf("Urgent pointer:         %d\n", tcp.UrgentPointer)
}

func parseTCPHeader(buf *bytes.Reader) (tcp TCP, err error) {
	/*
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          Source Port          |       Destination Port        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                        Sequence Number                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Acknowledgment Number                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  Data |           |U|A|P|R|S|F|                               |
	   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
	   |       |           |G|K|H|T|N|N|                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |           Checksum            |         Urgent Pointer        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Options                    |    Padding    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                             data                              |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	**/

	err = binary.Read(buf, binary.BigEndian, &tcp.SourcePort)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &tcp.DestinationPort)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &tcp.SequenceNumber)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &tcp.AcknowledgmentNumber)
	if err != nil {
		return
	}

	var temp uint16
	err = binary.Read(buf, binary.BigEndian, &temp)
	if err != nil {
		return
	}

	tcp.DataOffset = uint8(temp >> 12)
	tcp.Reserved = uint8(temp>>6) & 0x3F
	tcp.ControlBits = uint8(temp) & 0x3F

	err = binary.Read(buf, binary.BigEndian, &tcp.Window)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &tcp.Checksum)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &tcp.UrgentPointer)
	if err != nil {
		return
	}

	// Jump to the end of the header, which comprises `DataOffset` 32-bit words
	seek := tcp.DataOffset - 5
	buf.Seek(int64(seek)*4, io.SeekCurrent)

	return
}

func parseIPHeader(buf *bytes.Reader) (ip IP, err error) {
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

	// Jump to the end of the header, which comprises `HeaderLength` 32-bit words
	buf.Seek(int64(ip.HeaderLength)*4, io.SeekStart)

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

		reader := bytes.NewReader(buf[:n])

		ip, err := parseIPHeader(reader)
		if err == ErrNonIPv4 {
			continue
		}
		if err != nil {
			log.Fatal(err)
		}

		if ip.Protocol != 0x06 {
			// Not TCP
			continue
		}

		tcp, err := parseTCPHeader(reader)
		if err != nil {
			log.Fatal(err)
		}

		ip.Inspect()
		tcp.Inspect()
	}
}
