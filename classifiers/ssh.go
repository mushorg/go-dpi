package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

// SSHClassifier struct
type SSHClassifier struct{}

// HeuristicClassify for SMTPClassifier
func (classifier SSHClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			dstPort := layer.(*layers.TCP).DstPort
			if dstPort != 22 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// GetProtocol returns the corresponding protocol
func (classifier SSHClassifier) GetProtocol() godpi.Protocol {
	return godpi.Ssh
}
