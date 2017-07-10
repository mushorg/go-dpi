package classifiers

import (
	"testing"

	"github.com/mushorg/go-dpi"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
)

func TestClassifyFlow(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Error(err)
	}
	for i := 0; i < 3; i++ {
		<-dumpPackets
	}
	packet := <-dumpPackets
	flow := godpi.CreateFlowFromPacket(&packet)
	protocol, source := ClassifyFlow(flow)
	if protocol != godpi.Http || flow.DetectedProtocol != godpi.Http {
		t.Error("Wrong protocol detected:", protocol)
	}
	if name := flow.ClassificationSource; name != GoDPIName || source != GoDPIName {
		t.Error("Wrong classification source returned:", name)
	}
}

func TestClassifyFlowEmpty(t *testing.T) {
	flow := godpi.NewFlow()
	protocol, source := ClassifyFlow(flow)
	if protocol != godpi.Unknown || source != godpi.NoSource {
		t.Error("Protocol incorrectly detected:", protocol)
	}
}

func TestCheckFlowLayer(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Error(err)
	}
	flow := godpi.NewFlow()
	for packet := range dumpPackets {
		packetCopy := packet
		flow.AddPacket(&packetCopy)
	}
	noDetections := checkFlowLayer(flow, layers.LayerTypeTCP, func(layer gopacket.Layer) bool {
		_, ok := layer.(*layers.TCP)
		if !ok {
			t.Error("Invalid layer passed to callback")
		}
		return false
	})
	if noDetections {
		t.Error("Detection returned true when callback only returns false")
	}

	i := 0
	yesDetections := checkFlowLayer(flow, layers.LayerTypeTCP, func(layer gopacket.Layer) bool {
		i++
		return i == 10
	})
	if !yesDetections {
		t.Error("Detection should have returned true when callback returns true once")
	}
}

func TestCheckFirstPayload(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Error(err)
	}
	flow := godpi.NewFlow()
	for packet := range dumpPackets {
		packetCopy := packet
		flow.AddPacket(&packetCopy)
	}

	called := false
	noDetections := checkFirstPayload(flow, layers.LayerTypeTCP, func(payload []byte) bool {
		called = true
		if payload == nil || len(payload) == 0 {
			t.Error("No payload passed to callback")
		}
		if !strings.HasPrefix(string(payload), "GET /download.html") {
			t.Error("Wrong first payload passed to callback")
		}
		return false
	})
	if noDetections {
		t.Error("Detection returned true when callback returned false")
	}
	if !called {
		t.Error("Callback was never called")
	}
}
