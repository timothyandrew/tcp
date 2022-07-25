package main

import "fmt"

func formatIPAddress(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr>>24, (addr>>16)&0xFF, (addr>>8)&0xFF, addr&0xFF)
}

func add1sComplement(x, y uint16) uint16 {
	temp := int32(x) + int32(y)

	sum := uint16(temp & 0xFFFF)
	sum += uint16(temp >> 16)

	return sum
}
