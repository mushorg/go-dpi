// Package classifiers contains the custom classifiers for each protocol
// and the helpers for applying them on a flow.
package classifiers

import "github.com/mushorg/go-dpi"

// GoDPIName is the name of the library, to be used as an identifier for the
// source of a classification.
const GoDPIName = "go-dpi"

// GenericClassifier is implemented by every classifier. It contains a method
// that returns the classifier's detected protocol.
type GenericClassifier interface {
	// GetProtocol returns the protocol this classifier can detect.
	GetProtocol() godpi.Protocol
}

// HeuristicClassifier is implemented by the classifiers that have heuristic
// methods to detect a protocol.
type HeuristicClassifier interface {
	// HeuristicClassify returns whether this classifier can identify the flow
	// using heuristics.
	HeuristicClassify(*godpi.Flow) bool
}

var classifierList = [...]GenericClassifier{
	DnsClassifier{},
	FtpClassifier{},
	HttpClassifier{},
	IcmpClassifier{},
	NetbiosClassifier{},
	RdpClassifier{},
	RpcClassifier{},
	SmbClassifier{},
	SmtpClassifier{},
	SshClassifier{},
	SslClassifier{},
	HangoutClassifier{},
}

// ClassifyFlow applies all the classifiers to a flow and returns the protocol
// that is detected by a classifier if there is one. Otherwise, it returns nil.
func ClassifyFlow(flow *godpi.Flow) (result godpi.Protocol, source godpi.ClassificationSource) {
	for _, classifier := range classifierList {
		if heuristic, ok := classifier.(HeuristicClassifier); ok {
			if heuristic.HeuristicClassify(flow) {
				result = classifier.GetProtocol()
				source = GoDPIName
				flow.DetectedProtocol = result
				flow.ClassificationSource = GoDPIName
				break
			}
		}
	}
	return
}
