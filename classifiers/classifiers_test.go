package classifiers

import (
	"testing"

	"github.com/mushorg/go-dpi"
)

func TestClassifyFlow(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Error(err)
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
