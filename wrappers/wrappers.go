// Package wrappers contains wrappers for external libraries such as nDPI in
// order to use them for flow classification.
package wrappers

import (
	"strconv"
	"github.com/mushorg/go-dpi/types"
	"github.com/pkg/errors"
)

// Wrapper is implemented by every wrapper. It contains methods for
// initializing and destroying the wrapper, as well as for classifying a flow.
type Wrapper interface {
	InitializeWrapper() int
	DestroyWrapper() error
	ClassifyFlow(*types.Flow) (types.Protocol, error)
	GetWrapperName() types.ClassificationSource
}

var wrapperList = []Wrapper{
	NewLPIWrapper(),
	NewNDPIWrapper(),
}

var activeWrappers []Wrapper

// errorLibraryDisabled is returned from the initialization function of a
// wrapper that is set to be disabled in wrappers_config.h.
const errorLibraryDisabled = -0x1000

// WrapperError contains the error and the name of the wrapper for a wrapper
// that failed to initialize.
type WrapperError struct {
	error
	WrapperName types.ClassificationSource
}

// InitializeWrappers initializes all wrappers and filters out the ones
// that don't get initialized correctly.
// It returns the errors thrown during the initialization of the wrappers and
// the names of the wrappers that errored.
func InitializeWrappers() (errs []WrapperError) {
	errs = make([]WrapperError, 0)
	for _, wrapper := range wrapperList {
		errcode := wrapper.InitializeWrapper()
		if errcode == 0 {
			activeWrappers = append(activeWrappers, wrapper)
		} else if errcode != errorLibraryDisabled {
			errs = append(errs, WrapperError{errors.New(strconv.Itoa(errcode)), wrapper.GetWrapperName()})
		}
	}
	return
}

// DestroyWrappers destroys all active wrappers.
func DestroyWrappers() {
	for _, wrapper := range activeWrappers {
		wrapper.DestroyWrapper()
	}
}

// ClassifyFlow applies all the wrappers to a flow and returns the protocol
// that is detected by a wrapper if there is one. Otherwise, it returns nil.
func ClassifyFlow(flow *types.Flow) (result types.Protocol, source types.ClassificationSource) {
	for _, wrapper := range activeWrappers {
		if proto, err := wrapper.ClassifyFlow(flow); proto != types.Unknown && err == nil {
			result = proto
			source = wrapper.GetWrapperName()
			flow.DetectedProtocol = proto
			flow.ClassificationSource = source
			return
		}
	}
	return
}
