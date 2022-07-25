package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

type ConnectionState string

type Segment struct {
	SequenceNumber, AcknowledgementNumber, Length uint32
	Window, UrgentPointer, PrecedenceValue        uint32
}

type Connection struct {
	State ConnectionState

	SendUnacknowledged, SendNext, SendWindow, SendUrgentPointer uint32
	SendWL1, SendWL2, InitialSendSequenceNumber                 uint32

	ReceiveNext, ReceiveUrgentPointer, InitialReceiveSequenceNumber uint32
	ReceiveWindow                                                   uint16

	CurrentSendSegment    Segment
	CurrentReceiveSegment Segment
}

func (c *Connection) Initialize(header *TCP) {
	c.State = "LISTEN"

	c.InitialSendSequenceNumber = 512
	c.SendUnacknowledged = c.InitialSendSequenceNumber
	c.SendNext = c.InitialSendSequenceNumber + 1
	c.SendWindow = 1024

	c.InitialReceiveSequenceNumber = header.SequenceNumber
	c.ReceiveNext = header.SequenceNumber + 1
	c.ReceiveWindow = 1024
}

func (c *Connection) HandleSegment(header *TCP, payload *bytes.Reader) (response TCP, err error) {
	if c.State == "LISTEN" {
		if header.ControlBits&0x02 != 0x02 {
			err = fmt.Errorf("SYN bit not set")
			return
		}

		response.SourcePort = header.DestinationPort
		response.DestinationPort = header.SourcePort
		response.SequenceNumber = c.SendNext
		response.AcknowledgmentNumber = c.ReceiveNext
		response.DataOffset = 5

		response.ControlBits |= 0x02 // SYN
		response.ControlBits |= 0x10 // ACK

		response.Window = c.ReceiveWindow

		c.State = "SYN_RCVD"
		return
	}

	if c.State == "SYN_RCVD" {
		if header.ControlBits&0x10 != 0x10 {
			err = fmt.Errorf("SYN/ACK bits not set")
			return
		}

		c.SendUnacknowledged = header.AcknowledgmentNumber
		c.SendNext = header.AcknowledgmentNumber
		c.ReceiveNext = header.SequenceNumber + 1

		c.State = "ESTAB"
		return
	}

	if c.State == "ESTAB" {
		var n int64
		n, err = io.Copy(os.Stdout, payload)
		if err != nil {
			return response, err
		}

		c.ReceiveNext = header.SequenceNumber + uint32(n)
		response.AcknowledgmentNumber = c.ReceiveNext
		response.ControlBits |= 0x10 // ACK

		response.SequenceNumber = c.SendNext

		response.SourcePort = header.DestinationPort
		response.DestinationPort = header.SourcePort

		response.DataOffset = 5
		response.Window = c.ReceiveWindow

		return
	}

	return
}
