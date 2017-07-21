package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
)

// DNSClassifier struct
type DNSClassifier struct{}

// HeuristicClassify for DNSClassifier
func (classifier DNSClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFlowLayer(flow, layers.LayerTypeUDP, func(layer gopacket.Layer) (detected bool) {
		defer func() {
			if recover() != nil {
				// catch errors in the incorrect decoding of an irrelevant layer as DNS
				detected = false
			}
		}()
		layerParser := gopacket.DecodingLayerParser{}
		dns := layers.DNS{}
		err := dns.DecodeFromBytes(layer.LayerPayload(), &layerParser)
		// attempt to decode layer as DNS packet using gopacket and return
		// whether it was successful
		detected = err == nil
		return
	})
}

// GetProtocol returns the corresponding protocol
func (classifier DNSClassifier) GetProtocol() types.Protocol {
	return types.DNS
}
