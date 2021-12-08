package utils

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestReadDumpFile(t *testing.T) {
	var count int
	packets, err := ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	packet := <-packets
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer.SrcPort != 3372 || tcpLayer.DstPort != 80 || tcpLayer.Checksum != 0xC30C {
		t.Error("Wrong packet data read from dump")
	}
	count = 1
	for range packets {
		count++
	}
	if count != 43 {
		t.Errorf("Read wrong number of packets from dump: %d", count)
	}
}

func TestReadDumpInvalidFile(t *testing.T) {
	if _, err := ReadDumpFile("nonexistent.cap"); err == nil {
		t.Error("Did not throw error for nonexistent file")
	}
}
