package wrappers

import (
	"strings"
	"testing"

	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
)

func TestNewNDPIWrapper(t *testing.T) {
	if NewNDPIWrapper() == nil {
		t.Error("nDPI wrapper not created")
	}
}

func TestNDPIWrapperClassification(t *testing.T) {
	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	for i := 0; i < 4; i++ {
		packet := <-packetChan
		flow.Packets = append(flow.Packets, &packet)
	}

	wrapper := NewNDPIWrapper()
	wrapper.InitializeWrapper()
	result, err := wrapper.ClassifyFlow(flow)
	wrapper.DestroyWrapper()

	if result != types.HTTP || err != nil {
		t.Errorf("Incorrectly detected flow protocol: %v instead of HTTP", result)
	}
}

func TestNDPIWrapper_InitializeWrapper(t *testing.T) {
	wrapper := NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return 0 },
		},
	}
	// shouldn't be an error if 0 is returned
	if wrapper.InitializeWrapper() != 0 {
		t.Error("Error in wrapper initialization")
	}

	wrapper = NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return 1 },
		},
	}
	// should be an error if nonzero is returned
	if wrapper.InitializeWrapper() == 0 {
		t.Error("Wrapper initialization did not throw error")
	}
}

func TestNDPIWrapper_DestroyWrapper(t *testing.T) {
	destroyCalled := false
	wrapper := NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiDestroy: func() { destroyCalled = true },
		},
	}
	wrapper.DestroyWrapper()
	if !destroyCalled {
		t.Error("Wrapper destroy was not called")
	}
}

func TestNDPIWrapper_ClassifyFlowErrors(t *testing.T) {
	var retVal int32
	timesCalled := 0

	wrapper := &NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiPacketProcess: func(_, _, _ int, _ []byte) int32 {
				timesCalled++
				return retVal
			},
		},
	}

	// empty flow should be unknown
	if ret, _ := wrapper.ClassifyFlow(types.NewFlow()); ret != types.Unknown {
		t.Errorf("Incorrectly classified empty flow: %v instead of unknown", ret)
	}

	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	packet := <-packetChan
	flow.Packets = append(flow.Packets, &packet)

	// test nDPI error codes returning errors containing the correct strings
	returnValueErrors := map[int32]string{
		-10:  "IPv6",
		-11:  "fragmented",
		-12:  "flow",
		-100: "unknown",
	}

	for value, errStr := range returnValueErrors {
		retVal = value
		_, err := wrapper.ClassifyFlow(flow)
		if !strings.Contains(err.Error(), errStr) {
			t.Errorf("Incorrect error thrown for return value %d: %v", value, err.Error())
		}
	}
}

func TestNDPIWrapper_GetWrapperName(t *testing.T) {
	if name := NewNDPIWrapper().GetWrapperName(); name != NDPIWrapperName {
		t.Error("Wrong wrapper name returned:", name)
	}
}
