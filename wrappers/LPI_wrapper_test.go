package wrappers

import (
	"github.com/mushorg/go-dpi"
	"testing"
)

func TestNDPIWrapperClassifyFlow(t *testing.T) {
	wrapper := NewLPIWrapper()
	wrapper.InitializeWrapper()
	defer wrapper.DestroyWrapper()

	packetChan, _ := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")

	flow := godpi.NewFlow()
	for i := 0; i < 3; i++ {
		packet := <-packetChan
		flow.Packets = append(flow.Packets, &packet)
	}

	// first three packets should not be enough to classify the flow
	if result, _ := wrapper.ClassifyFlow(flow); result != godpi.Unknown {
		t.Errorf("Incorrectly detected %s instead of Unknown", result)
	}

	flow = godpi.NewFlow()
	packet := <-packetChan
	flow.Packets = append(flow.Packets, &packet)

	// fourth packet should be HTTP
	if result, _ := wrapper.ClassifyFlow(flow); result != godpi.HTTP {
		t.Errorf("Incorrectly detected %s instead of HTTP", result)
	}
}

func TestLPIWrapper_GetWrapperName(t *testing.T) {
	if name := NewLPIWrapper().GetWrapperName(); name != LPIWrapperName {
		t.Error("Wrong wrapper name returned:", name)
	}
}
