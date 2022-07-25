package main

import "bytes"

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

func (c *Connection) HandleSegment(header *TCP, payload *bytes.Reader) (response TCP) {
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
