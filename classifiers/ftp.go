package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

type FtpClassifier struct{}

func (_ FtpClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	if len(flow.Packets) == 0 {
		return false
	}
	for _, packet := range flow.Packets {
		if layer := (*packet).Layer(layers.LayerTypeTCP); layer != nil {
			srcPort := layer.(*layers.TCP).SrcPort
			dstPort := layer.(*layers.TCP).DstPort
			if srcPort != 21 && dstPort != 21 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func (_ FtpClassifier) GetProtocol() godpi.Protocol {
	return godpi.Ftp
}
