package godpi

import (
	"github.com/mushorg/go-dpi/modules/ml"
	"testing"
)

func TestMLOption(t *testing.T) {
	module := ml.NewLinearSVCModule()
	mlo := MLOption{TCPModelPath: "test_path", UDPModelPath: "test_path", Threshold: 0.8}
	mlo.Apply(module)
	module.Destroy()
	if module.TCPModelPath != mlo.TCPModelPath {
		t.Errorf("Expected TCPModelPath %s, got %s", mlo.TCPModelPath, module.TCPModelPath)
	}
	// Applied
}

func TestClassifierOption(t *testing.T) {
	// TODO
}
