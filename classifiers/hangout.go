package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type HangoutClassifier struct{}

func (_ HangoutClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) < 24 {
		return false
	}

	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if (srcPort < 19305 || srcPort > 19309) && (dstPort < 19305 || dstPort > 19309) {
				return false
			}

		} else if layer := (*packet).Layer(layers.LayerTypeUDP); layer != nil {
			srcPort := layer.(*layers.UDP).SrcPort
			dstPort := layer.(*layers.UDP).DstPort
			if (srcPort < 19302 || srcPort > 19309) && (dstPort < 19302 || srcPort > 19309) {
				return false
			}
		} else {
			return false
		}
	}

	return true

}

func (_ HangoutClassifier) GetProtocol() godpi.Protocol {
	return godpi.Hangout
}
