package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

// DNSClassifier struct
type DNSClassifier struct{}

// HeuristicClassify for DNSClassifier
func (_ DNSClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	return checkFlowLayer(flow, layers.LayerTypeUDP, func(layer gopacket.Layer) bool {
		layerParser := gopacket.DecodingLayerParser{}
		dns := layers.DNS{}
		err := dns.DecodeFromBytes(layer.LayerPayload(), &layerParser)
		// attempt to decode layer as DNS packet using gopacket and return
		// whether it was successful
		return err == nil
	})
}

// GetProtocol returns the corresponding protocol
func (classifier DNSClassifier) GetProtocol() godpi.Protocol {
	return godpi.Dns
}
