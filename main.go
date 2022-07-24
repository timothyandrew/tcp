package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/songgao/water"
)

var ErrInvalidIPHeader = fmt.Errorf("failed to parse IP header")
var ErrNonIPv4 = fmt.Errorf("can't handle non-IPv4 packets")

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
