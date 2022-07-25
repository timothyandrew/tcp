package main

import (
	"bytes"
	"log"

	"github.com/songgao/water"
)

type Quad struct {
	SourceIP, DestinationIP     uint32
	SourcePort, DestinationPort uint16
}

func main() {
	config := water.Config{DeviceType: water.TUN}
	config.Name = "tun_tcp"

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1500)
	connections := make(map[Quad]*Connection)

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

		if _, ok := connections[quad]; !ok {
			c := Connection{}
			c.Initialize(&tcp)
			connections[quad] = &c
		}

		c := connections[quad]
		respTcp, err := c.HandleSegment(&tcp, reader)
		if err != nil {
			log.Println("ERROR: ", err)
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
		response.Write(respTcp.Serialize(&respIp).Bytes())

		_, err = response.WriteTo(ifce)
		if err != nil {
			log.Fatal(err)
		}
	}
}
