package wrappers

import (
	"testing"

	"github.com/mushorg/go-dpi/types"
)

type MockWrapper struct {
	initializeSuccessfully bool
	initializeCalled       bool
	libraryDisabled        bool
	destroyCalled          bool
	classifyCalled         bool
}

func (wrapper *MockWrapper) InitializeWrapper() int {
	wrapper.initializeCalled = true
	if wrapper.initializeSuccessfully {
		return 0
	} else if wrapper.libraryDisabled {
		return errorLibraryDisabled
	} else {
		return -1
	}
}

func (wrapper *MockWrapper) DestroyWrapper() error {
	wrapper.destroyCalled = true
	return nil
}

func (wrapper *MockWrapper) ClassifyFlow(flow *types.Flow) (types.Protocol, error) {
	wrapper.classifyCalled = true
	return types.HTTP, nil
}

func (wrapper *MockWrapper) GetWrapperName() types.ClassificationSource {
	return "mock"
}

func TestClassifyFlowUninitialized(t *testing.T) {
	flow := types.NewFlow()
	uninitialized := &MockWrapper{initializeSuccessfully: false}
	module := NewWrapperModule()
	module.ConfigureModule(WrapperModuleConfig{
		Wrappers: []Wrapper{uninitialized},
	})
	module.Initialize()
	if !uninitialized.initializeCalled {
		t.Error("Initialize not called on wrapper")
	}
	result := module.ClassifyFlow(flow)
	if uninitialized.classifyCalled {
		t.Error("Classify called on uninitialized wrapper")
	}
	if result.Protocol != types.Unknown {
		t.Error("Empty classify did not return unknown")
	}
	if result.Source != types.NoSource {
		t.Error("Empty classify incorrectly returned source")
	}
	module.Destroy()
	if uninitialized.destroyCalled {
		t.Error("Destroy called on uninitialized wrapper")
	}
}

func TestClassifyFlowInitialized(t *testing.T) {
	flow := types.NewFlow()
	initialized := &MockWrapper{initializeSuccessfully: true, libraryDisabled: false}
	module := NewWrapperModule()
	module.ConfigureModule(WrapperModuleConfig{
		Wrappers: []Wrapper{initialized},
	})
	module.Initialize()
	if !initialized.initializeCalled {
		t.Error("Initialize not called on wrapper")
	}
	result := module.ClassifyFlow(flow)
	flowCls := flow.GetClassificationResult()
	if !initialized.classifyCalled {
		t.Error("Classify not called on active wrapper")
	}
	if result.Protocol != types.HTTP || flowCls.Protocol != types.HTTP {
		t.Error("Classify did not return correct result")
	}
	if result.Source != "mock" || flowCls.Source != "mock" {
		t.Error("Classify did not return correct result")
	}
	results := module.ClassifyFlowAll(flow)
	if len(results) != 1 {
		t.Error("ClassifyFlowAll didn't return one result")
	}
	if results[0] != result {
		t.Errorf("ClassifyFlowAll returned a different result from Classify: %v", results[0])
	}
	module.Destroy()
	if !initialized.destroyCalled {
		t.Error("Destroy not called on active wrapper")
	}
}

func TestWrapperLibraryDisabled(t *testing.T) {
	flow := types.NewFlow()
	disabled := &MockWrapper{initializeSuccessfully: false, libraryDisabled: true}
	module := NewWrapperModule()
	module.ConfigureModule(WrapperModuleConfig{
		Wrappers: []Wrapper{disabled},
	})
	module.Initialize()
	if !disabled.initializeCalled {
		t.Error("Initialize not called on wrapper")
	}
	result := module.ClassifyFlow(flow)
	if disabled.classifyCalled {
		t.Error("Classify called on disabled wrapper")
	}
	if result.Protocol != types.Unknown {
		t.Errorf("Classify returned a protocol without any wrappers: %v", result.Protocol)
	}
	module.Destroy()
	if disabled.destroyCalled {
		t.Error("Destroy called on disabled wrapper")
	}
}

func BenchmarkWrapperModule(b *testing.B) {
	module := NewWrapperModule()
	err := types.BenchmarkModule("../../godpi_example/dumps/", module, b.N)
	if err != nil {
		b.Error(err)
	}
}
