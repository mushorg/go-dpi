package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
)

// RDPClassifier struct
type RDPClassifier struct{}

// HeuristicClassify for RDPClassifier
func (classifier RDPClassifier) HeuristicClassify(flow *types.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if srcPort != 3389 && dstPort != 3389 {
				return false
			}
		} else if layer := (*packet).Layer(layers.LayerTypeUDP); layer != nil {
			srcPort := layer.(*layers.UDP).SrcPort
			dstPort := layer.(*layers.UDP).DstPort
			if srcPort != 3389 && dstPort != 3389 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// GetProtocol returns the corresponding protocol
func (classifier RDPClassifier) GetProtocol() types.Protocol {
	return types.RDP
}
