package classifiers

import "github.com/mushorg/go-dpi"

type GenericClassifier interface {
	GetProtocol() go_dpi.Protocol
}

type HeuristicClassifier interface {
	HeuristicClassify(go_dpi.Flow) bool
}
