package classifiers

import (
	"github.com/mushorg/go-dpi"
)

type HttpClassifier struct{}

func (_ HttpClassifier) HeuristicClassify(flow go_dpi.Flow) bool {
	return true
}

func (_ HttpClassifier) GetProtocol() go_dpi.Protocol {
	return go_dpi.Http
}
