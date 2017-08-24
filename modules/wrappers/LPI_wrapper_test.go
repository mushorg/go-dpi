package wrappers

import (
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
	"testing"
)

func TestLPIWrapperClassifyFlow(t *testing.T) {
	wrapper := NewLPIWrapper()
	switch errCode := wrapper.InitializeWrapper(); errCode {
	case 0:
		defer wrapper.DestroyWrapper()

		packetChan, _ := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")

		flow := types.NewFlow()
		for i := 0; i < 3; i++ {
			packet := <-packetChan
			flow.AddPacket(&packet)
		}

		// first three packets should not be enough to classify the flow
		if result, _ := wrapper.ClassifyFlow(flow); result != types.Unknown {
			t.Errorf("Incorrectly detected %v instead of Unknown", result)
		}

		flow = types.NewFlow()
		packet := <-packetChan
		flow.AddPacket(&packet)

		// fourth packet should be HTTP
		if result, _ := wrapper.ClassifyFlow(flow); result != types.HTTP {
			t.Errorf("Incorrectly detected %v instead of HTTP", result)
		}
	case errorLibraryDisabled:
		// do nothing if library is disabled
	default:
		t.Error("LPI initialization returned error code:", errCode)
	}
}

func TestLPIWrapper_GetWrapperName(t *testing.T) {
	if name := NewLPIWrapper().GetWrapperName(); name != LPIWrapperName {
		t.Error("Wrong wrapper name returned:", name)
	}
}
