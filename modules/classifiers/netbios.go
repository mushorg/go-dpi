package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
)

// NetBIOSClassifier struct
type NetBIOSClassifier struct{}

// HeuristicClassify for NetBIOSClassifier
func (classifier NetBIOSClassifier) HeuristicClassify(flow *types.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if srcPort != 139 && dstPort != 139 {
				return false
			}
		} else if layer := (*packet).Layer(layers.LayerTypeUDP); layer != nil {
			srcPort := layer.(*layers.UDP).SrcPort
			dstPort := layer.(*layers.UDP).DstPort
			if srcPort != 137 && srcPort != 138 && dstPort != 137 && dstPort != 138 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// GetProtocol returns the corresponding protocol
func (classifier NetBIOSClassifier) GetProtocol() types.Protocol {
	return types.NetBIOS
}
