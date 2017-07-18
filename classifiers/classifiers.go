// Package classifiers contains the custom classifiers for each protocol
// and the helpers for applying them on a flow.
package classifiers

import (
	"github.com/google/gopacket"
	"github.com/mushorg/go-dpi"
)

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
	DNSClassifier{},
	FTPClassifier{},
	HTTPClassifier{},
	ICMPClassifier{},
	NetBIOSClassifier{},
	RDPClassifier{},
	RPCClassifier{},
	SMBClassifier{},
	SMTPClassifier{},
	SSHClassifier{},
	SSLClassifier{},
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

// checkFlowLayer applies the check function to the specified layer of each
// packet in a flow, where it is available. It returns whether there is a
// packet in the flow for which the check function returns true.
func checkFlowLayer(flow *godpi.Flow, layerType gopacket.LayerType,
	checkFunc func(layer gopacket.Layer) bool) bool {
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layerType); layer != nil {
			if checkFunc(layer) {
				return true
			}
		}
	}
	return false
}

// checkFirstPayload applies the check function to the payload of the first
// packet that has the specified layer. It returns the result of that function
// on that first packet, or false if no such packet exists.
func checkFirstPayload(packets []*gopacket.Packet, layerType gopacket.LayerType,
	checkFunc func(payload []byte, packetsRest []*gopacket.Packet) bool) bool {
	for i, packet := range packets {
		if layer := (*packet).Layer(layerType); layer != nil {
			if payload := layer.LayerPayload(); payload != nil && len(payload) > 0 {
				return checkFunc(payload, packets[i+1:])
			}
		}
	}
	return false
}
