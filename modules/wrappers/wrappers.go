// Package wrappers contains wrappers for external libraries such as nDPI in
// order to use them for flow classification.
package wrappers

import (
	"github.com/mushorg/go-dpi/types"
	"github.com/pkg/errors"
	"strconv"
)

// WrapperModule is the module that contains wrappers for other protocol
// identification libraries.
type WrapperModule struct {
	wrapperList    []Wrapper
	activeWrappers []Wrapper
	WrapperErrors  []WrapperError
}

// Wrapper is implemented by every wrapper. It contains methods for
// initializing and destroying the wrapper, as well as for classifying a flow.
type Wrapper interface {
	InitializeWrapper() int
	DestroyWrapper() error
	ClassifyFlow(*types.Flow) (types.Protocol, error)
	GetWrapperName() types.ClassificationSource
}

// WrapperModuleConfig is given to the module's ConfigureModule method, in
// order to set which wrappers are active and their order.
type WrapperModuleConfig struct {
	Wrappers []Wrapper
}

// WrapperError contains the error and the name of the wrapper for a wrapper
// that failed to initialize.
type WrapperError struct {
	error
	WrapperName types.ClassificationSource
}

// errorLibraryDisabled is returned from the initialization function of a
// wrapper that is set to be disabled in wrappers_config.h.
const errorLibraryDisabled = -0x1000

// NewWrapperModule returns a new WrapperModule with the default configuration.
// By default, all wrappers will be enabled.
func NewWrapperModule() *WrapperModule {
	module := &WrapperModule{}
	module.activeWrappers = make([]Wrapper, 0)
	module.wrapperList = []Wrapper{
		NewLPIWrapper(),
		NewNDPIWrapper(),
	}
	return module
}

// Initialize initializes all wrappers and filters out the ones
// that don't get initialized correctly.
// It returns the errors thrown during the initialization of the wrappers and
// the names of the wrappers that errored.
func (module *WrapperModule) Initialize() error {
	module.WrapperErrors = make([]WrapperError, 0)
	for _, wrapper := range module.wrapperList {
		errcode := wrapper.InitializeWrapper()
		if errcode == 0 {
			module.activeWrappers = append(module.activeWrappers, wrapper)
		} else if errcode != errorLibraryDisabled {
			module.WrapperErrors = append(module.WrapperErrors, WrapperError{
				errors.New(strconv.Itoa(errcode)),
				wrapper.GetWrapperName()})
		}
	}
	if len(module.WrapperErrors) != 0 {
		return errors.New("Some wrappers did not initialize correctly")
	}
	return nil
}

// Destroy destroys all active wrappers.
func (module *WrapperModule) Destroy() error {
	for _, wrapper := range module.activeWrappers {
		wrapper.DestroyWrapper()
	}
	return nil
}

// ClassifyFlow applies all the wrappers to a flow and returns the protocol
// that is detected by a wrapper if there is one. Otherwise, it returns the
// Undefined protocol.
func (module *WrapperModule) ClassifyFlow(flow *types.Flow) (result types.ClassificationResult) {
	for _, wrapper := range module.activeWrappers {
		if proto, err := wrapper.ClassifyFlow(flow); proto != types.Unknown && err == nil {
			result.Protocol = proto
			result.Source = wrapper.GetWrapperName()
			flow.SetClassificationResult(result.Protocol, result.Source)
			return
		}
	}
	return
}

// ClassifyFlowAll applies all the wrappers to a flow and returns the protocols
// that are detected by each one in an array.
func (module *WrapperModule) ClassifyFlowAll(flow *types.Flow) (results []types.ClassificationResult) {
	for _, wrapper := range module.activeWrappers {
		if proto, err := wrapper.ClassifyFlow(flow); err == nil {
			var result types.ClassificationResult
			result.Protocol = proto
			result.Source = wrapper.GetWrapperName()
			flow.SetClassificationResult(result.Protocol, result.Source)
			results = append(results, result)
		}
	}
	return
}

// ConfigureModule configures this module instance with the given configuration.
// This should called before the module instance is initialized, otherwise
// Destroy and Initialize should be called on the module manually.
func (module *WrapperModule) ConfigureModule(config WrapperModuleConfig) {
	module.wrapperList = config.Wrappers
}
