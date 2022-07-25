package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
)

const (
	WRITE_BUFFER_BYTES = 1024
)

type ConnectionState string

type Connection struct {
	mu sync.Mutex

	State ConnectionState

	SendWindow                                      uint16
	SendUnacknowledged, SendNext, SendUrgentPointer uint32
	SendWL1, SendWL2, InitialSendSequenceNumber     uint32

	ReceiveNext, ReceiveUrgentPointer, InitialReceiveSequenceNumber uint32
	ReceiveWindow                                                   uint16
}

func (c *Connection) Write(buf []byte, quad Quad) (response TCP, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	response.SourcePort = quad.DestinationPort
	response.DestinationPort = quad.SourcePort
	response.SequenceNumber = c.SendNext
	response.AcknowledgmentNumber = c.ReceiveNext
	response.DataOffset = 5
	response.ControlBits |= 0x10 // ACK
	response.Window = 1024

	c.SendNext = response.SequenceNumber + uint32(len(buf))

	return
}

func (c *Connection) Initialize(header *TCP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.State = "LISTEN"

	c.InitialSendSequenceNumber = rand.Uint32()
	c.SendUnacknowledged = c.InitialSendSequenceNumber
	c.SendNext = c.InitialSendSequenceNumber + 1
	c.SendWindow = header.Window

	c.InitialReceiveSequenceNumber = header.SequenceNumber
	c.ReceiveNext = header.SequenceNumber + 1
	c.ReceiveWindow = 1024
}

func (c *Connection) HandleSegment(header *TCP, payload *bytes.Reader) (response TCP, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
		c.SendWindow = header.Window

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
		c.SendUnacknowledged = header.AcknowledgmentNumber
		c.SendWindow = header.Window

		// No new data, don't respond with an ACK
		if n == 0 {
			return
		}

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
