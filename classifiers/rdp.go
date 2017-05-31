package classifiers

import (
	"github.com/mushorg/go-dpi"
)

type RdpClassifier struct{}

func (_ RdpClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	return true
}

func (_ RdpClassifier) GetProtocol() godpi.Protocol {
	return godpi.Rdp
}
