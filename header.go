package main

import "fmt"

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
