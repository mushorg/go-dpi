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
	wrapperList = []Wrapper{
		uninitialized,
	}
	activeWrappers = []Wrapper{}
	InitializeWrappers()
	if !uninitialized.initializeCalled {
		t.Error("Initialize not called on wrapper")
	}
	result, source := ClassifyFlow(flow)
	if uninitialized.classifyCalled {
		t.Error("Classify called on uninitialized wrapper")
	}
	if result != types.Unknown {
		t.Error("Empty classify did not return unknown")
	}
	if source != types.NoSource {
		t.Error("Empty classify incorrectly returned source")
	}
	DestroyWrappers()
	if uninitialized.destroyCalled {
		t.Error("Destroy called on uninitialized wrapper")
	}
}

func TestClassifyFlowInitialized(t *testing.T) {
	flow := types.NewFlow()
	initialized := &MockWrapper{initializeSuccessfully: true, libraryDisabled: false}
	wrapperList = []Wrapper{
		initialized,
	}
	activeWrappers = []Wrapper{}
	InitializeWrappers()
	if !initialized.initializeCalled {
		t.Error("Initialize not called on wrapper")
	}
	result, source := ClassifyFlow(flow)
	if !initialized.classifyCalled {
		t.Error("Classify not called on active wrapper")
	}
	if result != types.HTTP || flow.DetectedProtocol != types.HTTP {
		t.Error("Classify did not return correct result")
	}
	if source != "mock" || flow.ClassificationSource != "mock" {
		t.Error("Classify did not return correct result")
	}
	DestroyWrappers()
	if !initialized.destroyCalled {
		t.Error("Destroy not called on active wrapper")
	}
}

func TestWrapperLibraryDisabled(t *testing.T) {
	flow := types.NewFlow()
	disabled := &MockWrapper{initializeSuccessfully: false, libraryDisabled: true}
	wrapperList = []Wrapper{
		disabled,
	}
	activeWrappers = []Wrapper{}
	InitializeWrappers()
	if !disabled.initializeCalled {
		t.Error("Initialize not called on wrapper")
	}
	result, _ := ClassifyFlow(flow)
	if disabled.classifyCalled {
		t.Error("Classify called on disabled wrapper")
	}
	if result != types.Unknown {
		t.Error("Classify returned a protocol without any wrappers", result)
	}
	DestroyWrappers()
	if disabled.destroyCalled {
		t.Error("Destroy called on disabled wrapper")
	}
}
