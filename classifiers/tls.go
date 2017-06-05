package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type TlsClassifier struct{}

func (_ TlsClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			dstPort := layer.(*layers.TCP).DstPort
			if dstPort != 443 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func (_ TlsClassifier) GetProtocol() godpi.Protocol {
	return godpi.Tls
}
