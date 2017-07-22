// Package godpi provides the main API interface for utilizing the go-dpi library.
package godpi

import (
	"github.com/google/gopacket"
	"github.com/mushorg/go-dpi/modules/classifiers"
	"github.com/mushorg/go-dpi/modules/wrappers"
	"github.com/mushorg/go-dpi/types"
)

// Module is implemented by every classification module provided by the
// library. Each module has its own initialization and destruction methods,
// as well as their own method for classifying a flow. They may also be
// enabled or disabled and usually will also provide a configuration method.
type Module interface {
	Initialize() error
	Destroy() error
	ClassifyFlow(*types.Flow) (types.Protocol, types.ClassificationSource)
}

var activatedModules []Module
var moduleList = []Module{
	classifiers.NewClassifierModule(),
	wrappers.NewWrapperModule(),
}

// Initialize initializes the library and the selected modules.
func Initialize() (errs []error) {
	for _, module := range moduleList {
		activated := false
		for _, activeModule := range activatedModules {
			if activeModule == module {
				activated = true
				break
			}
		}
		if !activated {
			err := module.Initialize()
			if err == nil {
				activatedModules = append(activatedModules, module)
			} else {
				errs = append(errs, err)
			}
		}
	}
	return
}

// Destroy frees all allocated resources and deactivates the active modules.
func Destroy() (errs []error) {
	newActivatedModules := make([]Module, 0)
	for _, module := range activatedModules {
		err := module.Destroy()
		if err != nil {
			newActivatedModules = append(newActivatedModules, module)
			errs = append(errs, err)
		}
	}
	activatedModules = newActivatedModules
	return
}

// SetModules selects the modules to be used by the library and their order.
// After calling this method, Initialize should be called, in order to
// initialize any new modules. If Initialize has already been called before,
// Destroy should be called as well before Initialize.
func SetModules(modules []Module) {
	moduleList = make([]Module, len(modules))
	copy(moduleList, modules)
}

// GetPacketFlow returns a Flow for the given type. If another packet has been
// processed before that was part of the same communication flow, the same
// Flow will be returned, with the new packet added. Otherwise, a new Flow
// will be created with only this packet.
// The function also returns whether the returned Flow is a new one, and not
// one that already existed.
func GetPacketFlow(packet *gopacket.Packet) (*types.Flow, bool) {
	return types.GetFlowForPacket(packet)
}

// ClassifyFlow takes a Flow and tries to classify it with all of the activated
// modules in order, until one of them manages to classify it. It returns
// the detected protocol as well as the source that made the classification.
// If no classification is made, the protocol Unknown is returned.
func ClassifyFlow(flow *types.Flow) (types.Protocol, types.ClassificationSource) {
	for _, module := range activatedModules {
		protocol, source := module.ClassifyFlow(flow)
		if protocol != types.Unknown {
			return protocol, source
		}
	}
	return types.Unknown, types.NoSource
}
