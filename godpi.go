// Package godpi provides the main API interface for utilizing the go-dpi library.
package godpi

import (
	"github.com/google/gopacket"
	"github.com/mushorg/go-dpi/modules/classifiers"
	"github.com/mushorg/go-dpi/modules/wrappers"
	"github.com/mushorg/go-dpi/types"
)

var activatedModules []types.Module
var moduleList = []types.Module{
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
	newActivatedModules := make([]types.Module, 0)
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
func SetModules(modules []types.Module) {
	moduleList = make([]types.Module, len(modules))
	copy(moduleList, modules)
}

// GetPacketFlow returns a Flow for the given packet. If another packet has
// been processed before that was part of the same communication flow, the same
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
func ClassifyFlow(flow *types.Flow) (result types.ClassificationResult) {
	for _, module := range activatedModules {
		resultTmp := module.ClassifyFlow(flow)
		if resultTmp.Protocol != types.Unknown {
			result = resultTmp
			return
		}
	}
	return
}

// ClassifyFlowAllModules takes a Flow and tries to classify it with all of the
// activated modules. However, as opposed to ClassifyFlow, it will return all
// of the results returned from the modules, not only the first successful one.
func ClassifyFlowAllModules(flow *types.Flow) (results []types.ClassificationResult) {
	for _, module := range activatedModules {
		resultsTmp := module.ClassifyFlowAll(flow)
		for _, resultTmp := range resultsTmp {
			if resultTmp.Protocol != types.Unknown {
				results = append(results, resultTmp)
			}
		}
	}
	return
}
