package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type IP struct {
	Version, HeaderLength, TypeOfService, Flags, TimeToLive, Protocol uint8
	TotalLength, Identification, FragmentOffset, HeaderChecksum       uint16
	SourceAddress, DestinationAddress                                 uint32
}

func (ip *IP) CalcChecksum() uint16 {
	var temp1, temp2 uint16
	temp1 |= uint16(ip.Version) << 12
	temp1 |= uint16(ip.HeaderLength) << 8
	temp1 |= uint16(ip.TypeOfService)

	temp2 |= uint16(ip.Flags) << 13
	temp2 |= uint16(ip.FragmentOffset)

	sum := uint16(0)
	sum = add1sComplement(sum, temp1)
	sum = add1sComplement(sum, ip.TotalLength)
	sum = add1sComplement(sum, ip.Identification)
	sum = add1sComplement(sum, temp2)
	sum = add1sComplement(sum, uint16(ip.TimeToLive)<<8)
	sum = add1sComplement(sum, uint16(ip.Protocol))
	sum = add1sComplement(sum, uint16(ip.SourceAddress>>16))
	sum = add1sComplement(sum, uint16(ip.SourceAddress&0xFFFF))
	sum = add1sComplement(sum, uint16(ip.DestinationAddress>>16))
	sum = add1sComplement(sum, uint16(ip.DestinationAddress&0xFFFF))

	return ^sum
}

func (ip *IP) Serialize() *bytes.Buffer {
	buf := bytes.NewBuffer([]byte{})
	ip.HeaderChecksum = ip.CalcChecksum()

	var temp uint16
	temp |= uint16(ip.Version) << 12
	temp |= uint16(ip.HeaderLength) << 8
	temp |= uint16(ip.TypeOfService)

	binary.Write(buf, binary.BigEndian, temp)
	binary.Write(buf, binary.BigEndian, ip.TotalLength)
	binary.Write(buf, binary.BigEndian, ip.Identification)

	temp = 0
	temp |= uint16(ip.Flags) << 13
	temp |= uint16(ip.FragmentOffset)

	binary.Write(buf, binary.BigEndian, temp)
	buf.WriteByte(ip.TimeToLive)
	buf.WriteByte(ip.Protocol)
	binary.Write(buf, binary.BigEndian, ip.HeaderChecksum)
	binary.Write(buf, binary.BigEndian, ip.SourceAddress)
	binary.Write(buf, binary.BigEndian, ip.DestinationAddress)

	return buf
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

func (t *TCP) CalcChecksum(ip *IP, payload []byte) uint16 {
	var temp uint16
	temp |= uint16(t.DataOffset) << 12
	temp |= uint16(t.ControlBits)

	sum := uint16(0)
	sum = add1sComplement(sum, uint16(ip.SourceAddress>>16))
	sum = add1sComplement(sum, uint16(ip.SourceAddress&0xFFFF))
	sum = add1sComplement(sum, uint16(ip.DestinationAddress>>16))
	sum = add1sComplement(sum, uint16(ip.DestinationAddress&0xFFFF))
	sum = add1sComplement(sum, uint16(ip.Protocol))
	sum = add1sComplement(sum, uint16(20+len(payload)))
	sum = add1sComplement(sum, t.SourcePort)
	sum = add1sComplement(sum, t.DestinationPort)
	sum = add1sComplement(sum, uint16(t.SequenceNumber>>16))
	sum = add1sComplement(sum, uint16(t.SequenceNumber&0xFFFF))
	sum = add1sComplement(sum, uint16(t.AcknowledgmentNumber>>16))
	sum = add1sComplement(sum, uint16(t.AcknowledgmentNumber&0xFFFF))
	sum = add1sComplement(sum, temp)
	sum = add1sComplement(sum, t.Window)
	sum = add1sComplement(sum, t.UrgentPointer)

	for i := 0; i < len(payload)/2; i++ {
		sum = add1sComplement(sum, uint16(payload[i*2])<<8+uint16(payload[(i*2)+1]))
	}

	if len(payload)%2 != 0 {
		sum = add1sComplement(sum, uint16(payload[len(payload)-1])<<8+uint16(0x00))
	}

	return ^sum
}

func (t *TCP) Serialize(ip *IP, payload []byte) *bytes.Buffer {
	buf := bytes.NewBuffer([]byte{})

	var temp uint16
	temp |= uint16(t.DataOffset) << 12
	temp |= uint16(t.ControlBits)

	t.Checksum = t.CalcChecksum(ip, payload)

	binary.Write(buf, binary.BigEndian, t.SourcePort)
	binary.Write(buf, binary.BigEndian, t.DestinationPort)
	binary.Write(buf, binary.BigEndian, t.SequenceNumber)
	binary.Write(buf, binary.BigEndian, t.AcknowledgmentNumber)
	binary.Write(buf, binary.BigEndian, temp)
	binary.Write(buf, binary.BigEndian, t.Window)
	binary.Write(buf, binary.BigEndian, t.Checksum)
	binary.Write(buf, binary.BigEndian, t.UrgentPointer)

	buf.Write(payload)

	return buf
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
