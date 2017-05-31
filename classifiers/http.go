package classifiers

import (
	"github.com/mushorg/go-dpi"
)

type HttpClassifier struct{}

func (_ HttpClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	return true
}

func (_ HttpClassifier) GetProtocol() godpi.Protocol {
	return godpi.Http
}
