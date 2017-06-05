package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type RpcClassifier struct{}

func (_ RpcClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if srcPort != 135 && dstPort != 135 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func (_ RpcClassifier) GetProtocol() godpi.Protocol {
	return godpi.Rpc
}
