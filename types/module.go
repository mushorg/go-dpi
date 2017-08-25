package types

import (
	"github.com/mushorg/go-dpi/utils"
	"github.com/pkg/errors"
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
func BenchmarkModule(dumpsDir string, module Module, times int) error {
	files, err := ioutil.ReadDir(dumpsDir)
	if err != nil {
		return err
	}
	InitCache(-1)
	defer DestroyCache()
	module.Initialize()
	defer module.Destroy()
	for i := 0; i < times; i++ {
		// gather all flows in all files
		for _, fInfo := range files {
			filePath := path.Join(dumpsDir, fInfo.Name())
			dumpPackets, err := utils.ReadDumpFile(filePath)
			if err != nil {
				return err
			}
			for p := range dumpPackets {
				flow, _ := GetFlowForPacket(&p)
				if flow.GetClassificationResult().Protocol == Unknown {
					module.ClassifyFlow(flow)
				}
			}
		}
	}
	return nil
}

// MockModule is used in tests in order to test the functionality of modules.
type MockModule struct {
	InitSuccess     bool
	InitCalled      int
	DestroySuccess  bool
	DestroyCalled   int
	ClassifySuccess bool
	ClassifyCalled  int
	SourceName      string
}

// Initialize logs the initialization of the mock module.
func (module *MockModule) Initialize() error {
	module.InitCalled++
	if module.InitSuccess {
		return nil
	}
	return errors.New("Init error")
}

// Destroy logs the destruction of the mock module.
func (module *MockModule) Destroy() error {
	module.DestroyCalled++
	if module.DestroySuccess {
		return nil
	}
	return errors.New("Destroy error")
}

// ClassifyFlow logs the classification by the mock module.
func (module *MockModule) ClassifyFlow(flow *Flow) (result ClassificationResult) {
	module.ClassifyCalled++
	result.Source = ClassificationSource(module.SourceName)
	if module.ClassifySuccess {
		result.Protocol = HTTP
	} else {
		result.Protocol = Unknown
	}
	return
}

// ClassifyFlowAll logs the multiple classification by the mock module.
func (module *MockModule) ClassifyFlowAll(flow *Flow) (results []ClassificationResult) {
	results = append(results, module.ClassifyFlow(flow))
	return
}
