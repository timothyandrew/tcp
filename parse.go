package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

var ErrInvalidIPHeader = fmt.Errorf("failed to parse IP header")
var ErrNonIPv4 = fmt.Errorf("can't handle non-IPv4 packets")

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

	// TODO: Parse options

	// Jump to the end of the header, which comprises `DataOffset` 32-bit words
	seek := tcp.DataOffset - 5
	buf.Seek(int64(seek)*4, io.SeekCurrent)

	return
}
