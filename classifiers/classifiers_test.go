package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mushorg/go-dpi"
	"testing"
)

func TestClassifyFlow(t *testing.T) {
	handle, err := pcap.OpenOffline("../examples/dumps/http.cap")
	if err != nil {
		t.Error(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	packet := <-packetSource
	flow := godpi.CreateFlowFromPacket(&packet)
	protocol := ClassifyFlow(flow)
	if protocol != godpi.Http {
		t.Error("Wrong protocol detected")
	}
}
