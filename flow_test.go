package godpi

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"testing"
)

func TestNewFlow(t *testing.T) {
	flow := NewFlow()
	if len(flow.Packets) != 0 {
		t.Error("New flow is not empty")
	}
}

func TestCreateFlowFromPacket(t *testing.T) {
	packet := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	flow := CreateFlowFromPacket(&packet)
	if len(flow.Packets) != 1 || flow.Packets[0] != &packet {
		t.Error("Flow doesn't have only the given packet")
	}
}
