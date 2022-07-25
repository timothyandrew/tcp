package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/songgao/water"
)

type Quad struct {
	SourceIP, DestinationIP     uint32
	SourcePort, DestinationPort uint16
}

type Connections struct {
	m   map[Quad]*Connection
	ids []Quad
}

func (c *Connections) Inspect() {
	fmt.Printf("%d connections:\n", len(c.m))
	for i, quad := range c.ids {
		if _, ok := c.m[quad]; ok {
			fmt.Printf("%d: %+v %v\n", i, quad, c.m[quad])
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixMilli())

	config := water.Config{DeviceType: water.TUN}
	config.Name = "tun_tcp"

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1500)
	connections := Connections{m: make(map[Quad]*Connection)}

	go repl(ifce, &connections)

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

		quad := Quad{
			SourceIP: ip.SourceAddress, DestinationIP: ip.DestinationAddress,
			SourcePort: tcp.SourcePort, DestinationPort: tcp.DestinationPort,
		}

		if _, ok := connections.m[quad]; !ok {
			c := Connection{}
			c.Initialize(&tcp)
			connections.m[quad] = &c
			connections.ids = append(connections.ids, quad)
		}

		c := connections.m[quad]
		respTcp, err := c.HandleSegment(&tcp, reader)
		if err != nil {
			// Error handling segment, remove connection
			delete(connections.m, quad)
			continue
		}

		if respTcp == (TCP{}) {
			continue
		}

		respIp := IP{
			Version:            4,
			HeaderLength:       5,
			TotalLength:        10 * 4,
			TimeToLive:         64,
			Flags:              2,
			Protocol:           6,
			SourceAddress:      ip.DestinationAddress,
			DestinationAddress: ip.SourceAddress,
		}

		response := respIp.Serialize()
		response.Write(respTcp.Serialize(&respIp, []byte{}).Bytes())

		_, err = response.WriteTo(ifce)
		if err != nil {
			log.Fatal(err)
		}
	}
}
