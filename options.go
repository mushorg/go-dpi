// Package godpi provides the main API interface for utilizing the go-dpi library.
package godpi

import (
	"github.com/mushorg/go-dpi/modules/classifiers"
	"github.com/mushorg/go-dpi/modules/ml"
	"github.com/mushorg/go-dpi/types"
)

// Options allow end users init module with custom options
// NOTE. it's necessary to check the module passed in Apply func
type Options interface {
	Apply(types.Module)
}

// MLOption take ml module options to override default values
type MLOption struct {
	TCPModelPath string
	UDPModelPath string
	Threshold    float32
}

// Apply ml module option to LinearSVCModule
func (o MLOption) Apply(mod types.Module) {
	// check module
	lsm, ok := mod.(*ml.LinearSVCModule)
	if !ok {
		return
	}
	if o.TCPModelPath != "" {
		lsm.TCPModelPath = o.TCPModelPath
	}
	if o.UDPModelPath != "" {
		lsm.UDPModelPath = o.UDPModelPath
	}
	if o.Threshold > 0.0 {
		lsm.Threshold = o.Threshold
	}
}

// ClassifierOption take classifier options to override default values
// for now this option was added for test
type ClassifierOption struct {
	// TODO
}

func (o ClassifierOption) Apply(mod types.Module) {
	// check module
	if _, ok := mod.(*classifiers.ClassifierModule); !ok {
		return
	}
	// TODO
}
