package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type SmbClassifier struct{}

func (_ SmbClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if srcPort != 445 && dstPort != 445 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func (_ SmbClassifier) GetProtocol() godpi.Protocol {
	return godpi.Smb
}
