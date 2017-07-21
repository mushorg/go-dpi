// Package wrappers contains wrappers for external libraries such as nDPI in
// order to use them for flow classification.
package wrappers

import (
	"fmt"

	"github.com/mushorg/go-dpi/types"
	"os"
)

// Wrapper is implemented by every wrapper. It contains methods for
// initializing and destroying the wrapper, as well as for classifying a flow.
type Wrapper interface {
	InitializeWrapper() error
	DestroyWrapper() error
	ClassifyFlow(*types.Flow) (types.Protocol, error)
	GetWrapperName() types.ClassificationSource
}

var wrapperList = []Wrapper{
	NewLPIWrapper(),
	NewNDPIWrapper(),
}

var activeWrappers []Wrapper

// InitializeWrappers initializes all wrappers and filters out the ones
// that don't get initialized correctly.
func InitializeWrappers() {
	for _, wrapper := range wrapperList {
		err := wrapper.InitializeWrapper()
		if err == nil {
			activeWrappers = append(activeWrappers, wrapper)
		} else {
			fmt.Fprintf(os.Stderr, "Error initializing wrapper: %s: %s\n",
				wrapper.GetWrapperName(), err)
		}
	}
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
