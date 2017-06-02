package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type RdpClassifier struct{}

func (_ RdpClassifier) HeuristicClassify(flow *godpi.Flow) bool {
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

func (_ RdpClassifier) GetProtocol() godpi.Protocol {
	return godpi.Rdp
}
