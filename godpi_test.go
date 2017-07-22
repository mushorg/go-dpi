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

func (module *mockModule) ClassifyFlow(flow *types.Flow) (protocol types.Protocol, source types.ClassificationSource) {
	module.classifyCalled++
	source = types.ClassificationSource(module.sourceName)
	if module.classifySuccess {
		protocol = types.HTTP
	} else {
		protocol = types.Unknown
	}
	return
}

func TestInitializeError(t *testing.T) {
	module := &mockModule{initSuccess: false}
	SetModules([]Module{module})
	errors := Initialize()
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from initializing, got %d", errNum)
	}
	if module.initCalled != 1 {
		t.Error("Initialize not called once")
	}
	result, source := ClassifyFlow(types.NewFlow())
	if module.classifyCalled != 0 {
		t.Error("Classify called on errored module")
	}
	if result != types.Unknown || source != types.NoSource {
		t.Errorf("Expected no result, got protocol %v from source %v", result, source)
	}
	Destroy()
	if module.destroyCalled != 0 {
		t.Error("Destroy called on errored module")
	}
}

func TestDestroyError(t *testing.T) {
	module := &mockModule{initSuccess: true, destroySuccess: false}
	SetModules([]Module{module})
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
	SetModules([]Module{noClsModule, clsModule, clsModule2})
	errors := Initialize()
	if errNum := len(errors); errNum != 0 {
		t.Errorf("Expected no errors to be returned from initializing, got %d", errNum)
	}
	if noClsModule.initCalled != 1 || clsModule.initCalled != 1 || clsModule2.initCalled != 1 {
		t.Error("Initialize not called on all modules once")
	}
	result, source := ClassifyFlow(types.NewFlow())
	if noClsModule.classifyCalled != 1 || clsModule.classifyCalled != 1 {
		t.Error("Classify not called on first two modules")
	}
	if clsModule2.classifyCalled != 0 {
		t.Error("Classify called on third module")
	}
	if result != types.HTTP || source != "module2" {
		t.Errorf("Expected HTTP from module2, got protocol %v from source %v", result, source)
	}
	Destroy()
	if noClsModule.destroyCalled != 1 || clsModule.destroyCalled != 1 || clsModule2.destroyCalled != 1 {
		t.Error("Destroy not called on all modules")
	}
}

func TestDoubleInitialize(t *testing.T) {
	module := &mockModule{initSuccess: true}
	SetModules([]Module{module})
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
