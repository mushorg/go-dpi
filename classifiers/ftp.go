package classifiers

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

// FTPClassifier struct
type FTPClassifier struct{}

// HeuristicClassify for FTPClassifier
func (classifier FTPClassifier) HeuristicClassify(flow *godpi.Flow) bool {
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

// GetProtocol returns the corresponding protocol
func (classifier FTPClassifier) GetProtocol() godpi.Protocol {
	return godpi.FTP
}
