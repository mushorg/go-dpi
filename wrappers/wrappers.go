// Package wrappers contains wrappers for external libraries such as nDPI in
// order to use them for flow classification.
package wrappers

import (
	"fmt"
	"github.com/mushorg/go-dpi"
)

// Wrapper is implemented by every wrapper. It contains methods for
// initializing and destroying the wrapper, as well as for classifying a flow.
type Wrapper interface {
	InitializeWrapper() error
	DestroyWrapper() error
	ClassifyFlow(*godpi.Flow) (godpi.Protocol, error)
}

var wrappersList = [...]Wrapper{
	NewNDPIWrapper(),
}

var activeWrappers []Wrapper

// InitializeWrappers initializes all wrappers and filters out the ones
// that don't get initialized correctly.
func InitializeWrappers() {
	for _, wrapper := range wrappersList {
		err := wrapper.InitializeWrapper()
		if err == nil {
			activeWrappers = append(activeWrappers, wrapper)
		} else {
			fmt.Println("Error initializing wrapper:", err)
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
func ClassifyFlow(flow *godpi.Flow) (result godpi.Protocol) {
	for _, wrapper := range activeWrappers {
		if proto, err := wrapper.ClassifyFlow(flow); proto != godpi.Unknown && err == nil {
			return proto
		}
	}
	return godpi.Unknown
}
