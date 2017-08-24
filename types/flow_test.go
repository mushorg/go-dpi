package types

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/utils"
)

func TestNewFlow(t *testing.T) {
	flow := NewFlow()
	if len(flow.GetPackets()) != 0 {
		t.Error("New flow is not empty")
	}
}

func TestCreateFlowFromPacket(t *testing.T) {
	packet := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.DecodeOptions{})
	flow := CreateFlowFromPacket(&packet)
	packets := flow.GetPackets()
	if len(packets) != 1 || *packets[0] != packet {
		t.Error("Flow doesn't have only the given packet")
	}
}

func TestGetFlowForPacket(t *testing.T) {
	InitCache(-1)
	defer DestroyCache()
	flows := make([]*Flow, 0)
	dumpPackets, err := utils.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	for packet := range dumpPackets {
		packetCopy := packet
		detectedFlow, isNew := GetFlowForPacket(&packetCopy)
		if isNew {
			flows = append(flows, detectedFlow)
		}
	}
	if count := len(flows); count != 3 {
		t.Fatalf("Wrong number of flows detected: %d instead of 3", count)
	}
	packetCounts := [3]int{34, 2, 7}
	for flowIdx, expectedCount := range packetCounts {
		if count := len(flows[flowIdx].GetPackets()); count != expectedCount {
			t.Errorf("Wrong number of packets in flow: %d instead of %d", count, expectedCount)
		}
	}
}

func TestFlushTrackedFlows(t *testing.T) {
	InitCache(-1)
	defer DestroyCache()
	dumpPackets, err := utils.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	packet := <-dumpPackets
	_, isNew := GetFlowForPacket(&packet)
	if !isNew {
		t.Error("Detected existing flow for first packet in flow")
	}
	_, isNew = GetFlowForPacket(&packet)
	if isNew {
		t.Error("Didn't detect existing flow for second packet in flow")
	}
	FlushTrackedFlows()
	_, isNew = GetFlowForPacket(&packet)
	if !isNew {
		t.Error("Detected existing flow for first packet after flush")
	}
}

func TestClassificationResultString(t *testing.T) {
	result := ClassificationResult{Protocol: "proto", Source: "src"}
	if resStr := result.String(); resStr != "Detected protocol proto from source src" {
		t.Errorf("Wrong string returned: %v", resStr)
	}
}
