package types

import (
	"github.com/mushorg/go-dpi/utils"
	"io/ioutil"
	"path"
)

// Module is implemented by every classification module provided by the
// library. Each module has its own initialization and destruction methods,
// as well as their own method for classifying a flow. They may also be
// enabled or disabled and usually will also provide a configuration method.
type Module interface {
	Initialize() error
	Destroy() error
	ClassifyFlow(*Flow) ClassificationResult
	ClassifyFlowAll(*Flow) []ClassificationResult
}

// BenchmarkModule runs a module on all available dump files. It is used
// for benchmarking the modules.
func BenchmarkModule(dumpsDir string, module Module) error {
	files, err := ioutil.ReadDir(dumpsDir)
	if err != nil {
		return err
	}
	FlushTrackedFlows()
	module.Initialize()
	defer module.Destroy()
	// gather all flows in all files
	for _, fInfo := range files {
		filepath := path.Join(dumpsDir, fInfo.Name())
		dumpPackets, err := utils.ReadDumpFile(filepath)
		if err != nil {
			return err
		}
		for p := range dumpPackets {
			flow, _ := GetFlowForPacket(&p)
			if flow.DetectedProtocol == Unknown {
				module.ClassifyFlow(flow)
			}
		}
	}
	return nil
}
