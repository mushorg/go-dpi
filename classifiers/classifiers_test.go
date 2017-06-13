package classifiers

import (
	"github.com/mushorg/go-dpi"
	"testing"
)

func TestClassifyFlow(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../examples/dumps/http.cap")
	if err != nil {
		t.Error(err)
	}
	packet := <-dumpPackets
	flow := godpi.CreateFlowFromPacket(&packet)
	protocol := ClassifyFlow(flow)
	if protocol != godpi.Http {
		t.Error("Wrong protocol detected:", protocol)
	}
}

func TestClassifyFlowEmpty(t *testing.T) {
	flow := godpi.NewFlow()
	protocol := ClassifyFlow(flow)
	if protocol != godpi.Unknown {
		t.Error("Protocol incorrectly detected:", protocol)
	}
}
