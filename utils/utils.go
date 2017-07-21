// Package utils provides some useful utility functions to the library.
package utils

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ReadDumpFile takes the path of a packet capture dump file and returns a
// channel that contains the packets in that file.
func ReadDumpFile(filename string) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource.Packets(), nil
}
