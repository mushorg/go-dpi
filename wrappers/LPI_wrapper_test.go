package wrappers

import (
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
	"testing"
)

func TestNDPIWrapperClassifyFlow(t *testing.T) {
	wrapper := NewLPIWrapper()
	wrapper.InitializeWrapper()
	defer wrapper.DestroyWrapper()

	packetChan, _ := utils.ReadDumpFile("../godpi_example/dumps/http.cap")

	flow := types.NewFlow()
	for i := 0; i < 3; i++ {
		packet := <-packetChan
		flow.Packets = append(flow.Packets, &packet)
	}

	// first three packets should not be enough to classify the flow
	if result, _ := wrapper.ClassifyFlow(flow); result != types.Unknown {
		t.Errorf("Incorrectly detected %v instead of Unknown", result)
	}

	flow = types.NewFlow()
	packet := <-packetChan
	flow.Packets = append(flow.Packets, &packet)

	// fourth packet should be HTTP
	if result, _ := wrapper.ClassifyFlow(flow); result != types.HTTP {
		t.Errorf("Incorrectly detected %v instead of HTTP", result)
	}
}

func TestLPIWrapper_GetWrapperName(t *testing.T) {
	if name := NewLPIWrapper().GetWrapperName(); name != LPIWrapperName {
		t.Error("Wrong wrapper name returned:", name)
	}
}
