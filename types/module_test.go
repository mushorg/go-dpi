package types

import (
	"testing"
)

func TestBenchmarkModule(t *testing.T) {
	module := &MockModule{}
	err := BenchmarkModule("noDir", module)
	if err == nil {
		t.Error("Got no error when giving an invalid directory")
	}
	err = BenchmarkModule("./", module)
	if err == nil {
		t.Error("Got no error when giving a directory with no dump files")
	}
	if module.ClassifyCalled != 0 {
		t.Error("Classify called without any valid pcap files")
	}
	err = BenchmarkModule("../godpi_example/dumps/", module)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if module.ClassifyCalled == 0 {
		t.Error("Classify not called in benchmark")
	}
}
