package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/songgao/water"
)

func dispatch(line string, iface *water.Interface, connections *Connections) {
	if line == "c" || line == "connections" {
		connections.Inspect()
	}

	if strings.HasPrefix(line, "write") {
		words := strings.Split(line, " ")
		if len(words) != 3 {
			fmt.Fprintf(os.Stderr, "usage: write <conn_id> <text>\n")
			return
		}

		connId, err := strconv.ParseInt(words[1], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "conn_id must be a number")
			return
		}
		text := []byte(words[2])

		quad := connections.ids[connId]
		respTcp, err := connections.m[quad].Write(text, quad)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to send data: %s", err.Error())
			return
		}

		respIp := IP{
			Version:            4,
			HeaderLength:       5,
			TotalLength:        (10 * 4) + uint16(len(text)),
			TimeToLive:         64,
			Flags:              2,
			Protocol:           6,
			SourceAddress:      quad.DestinationIP,
			DestinationAddress: quad.SourceIP,
		}

		response := respIp.Serialize()
		response.Write(respTcp.Serialize(&respIp, text).Bytes())

		_, err = response.WriteTo(iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write TCP data on the wire %s", err.Error())
			return
		}
	}
}

func repl(iface *water.Interface, connections *Connections) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		dispatch(strings.TrimSpace(line), iface, connections)
	}
}
