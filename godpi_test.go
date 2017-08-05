package godpi

import (
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
	"github.com/pkg/errors"
	"testing"
)

type mockModule struct {
	initSuccess     bool
	initCalled      int
	destroySuccess  bool
	destroyCalled   int
	classifySuccess bool
	classifyCalled  int
	sourceName      string
}

func (module *mockModule) Initialize() error {
	module.initCalled++
	if module.initSuccess {
		return nil
	}
	return errors.New("Init error")
}

func (module *mockModule) Destroy() error {
	module.destroyCalled++
	if module.destroySuccess {
		return nil
	}
	return errors.New("Destroy error")
}

func (module *mockModule) ClassifyFlow(flow *types.Flow) (result types.ClassificationResult) {
	module.classifyCalled++
	result.Source = types.ClassificationSource(module.sourceName)
	if module.classifySuccess {
		result.Protocol = types.HTTP
	} else {
		result.Protocol = types.Unknown
	}
	return
}

func (module *mockModule) ClassifyFlowAll(flow *types.Flow) (results []types.ClassificationResult) {
	results = append(results, module.ClassifyFlow(flow))
	return
}

func TestInitializeError(t *testing.T) {
	module := &mockModule{initSuccess: false}
	SetModules([]types.Module{module})
	errors := Initialize()
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from initializing, got %d", errNum)
	}
	if module.initCalled != 1 {
		t.Error("Initialize not called once")
	}
	result := ClassifyFlow(types.NewFlow())
	if module.classifyCalled != 0 {
		t.Error("Classify called on errored module")
	}
	if result.Protocol != types.Unknown || result.Source != types.NoSource {
		t.Errorf("Expected no result, got protocol %v from source %v", result.Protocol, result.Source)
	}
	Destroy()
	if module.destroyCalled != 0 {
		t.Error("Destroy called on errored module")
	}
}

func TestDestroyError(t *testing.T) {
	module := &mockModule{initSuccess: true, destroySuccess: false}
	SetModules([]types.Module{module})
	Initialize()
	errors := Destroy()
	if module.destroyCalled != 1 {
		t.Error("Destroy not called on module")
	}
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from destroying, got %d", errNum)
	}
	errors = Destroy()
	if module.destroyCalled != 2 {
		t.Error("Destroy not called again on module")
	}
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from destroying the second time, got %d", errNum)
	}
}

func TestClassifyFlow(t *testing.T) {
	noClsModule := &mockModule{initSuccess: true, classifySuccess: false, destroySuccess: true, sourceName: "module1"}
	clsModule := &mockModule{initSuccess: true, classifySuccess: true, destroySuccess: true, sourceName: "module2"}
	clsModule2 := &mockModule{initSuccess: true, classifySuccess: true, destroySuccess: true, sourceName: "module3"}
	SetModules([]types.Module{noClsModule, clsModule, clsModule2})
	errors := Initialize()
	if errNum := len(errors); errNum != 0 {
		t.Errorf("Expected no errors to be returned from initializing, got %d", errNum)
	}
	if noClsModule.initCalled != 1 || clsModule.initCalled != 1 || clsModule2.initCalled != 1 {
		t.Error("Initialize not called on all modules once")
	}
	result := ClassifyFlow(types.NewFlow())
	if noClsModule.classifyCalled != 1 || clsModule.classifyCalled != 1 {
		t.Error("Classify not called on first two modules")
	}
	if clsModule2.classifyCalled != 0 {
		t.Error("Classify called on third module")
	}
	if result.Protocol != types.HTTP || result.Source != "module2" {
		t.Errorf("Expected HTTP from module2, got protocol %v from source %v", result.Protocol, result.Source)
	}
	results := ClassifyFlowAllModules(types.NewFlow())
	if results[0] != result {
		t.Errorf("ClassifyFlowAllModules returned different result: %v", results[0])
	}
	Destroy()
	if noClsModule.destroyCalled != 1 || clsModule.destroyCalled != 1 || clsModule2.destroyCalled != 1 {
		t.Error("Destroy not called on all modules")
	}
}

func TestDoubleInitialize(t *testing.T) {
	module := &mockModule{initSuccess: true}
	SetModules([]types.Module{module})
	Initialize()
	if module.initCalled != 1 {
		t.Error("Initialize not called once")
	}
	Initialize()
	if module.initCalled != 1 {
		t.Error("Initialize called again for initialized module")
	}
}

func TestGetPacketFlow(t *testing.T) {
	dumpPackets, err := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	packet := <-dumpPackets
	flowFirst, isNew := GetPacketFlow(&packet)
	if !isNew {
		t.Error("Not new flow for first packet")
	}
	for i := 0; i < 3; i++ {
		packet := <-dumpPackets
		flowNext, isNew := GetPacketFlow(&packet)
		if isNew {
			t.Error("New flow returned for packet in existing flow")
		}
		if flowNext != flowFirst {
			t.Error("Wrong existing flow returned")
		}
	}
}
