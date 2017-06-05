package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type DnsClassifier struct{}

func (_ DnsClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeUDP); layer != nil {
			srcPort := layer.(*layers.UDP).SrcPort
			dstPort := layer.(*layers.UDP).DstPort
			if srcPort != 53 && dstPort != 53 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func (_ DnsClassifier) GetProtocol() godpi.Protocol {
	return godpi.Dns
}
