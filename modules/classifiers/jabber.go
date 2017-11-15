package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
	"regexp"
)

// JABBERClassifier struct
type JABBERClassifier struct{}

// HeuristicClassify for JABBERClassifier
func (classifier JABBERClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []gopacket.Packet) bool {
			payloadStr := string(payload)
			result, _ := regexp.MatchString("<?xml\\sversion='\\d+.\\d+'?.*", payloadStr)
			return result
		})
}

// GetProtocol returns the corresponding protocol
func (classifier JABBERClassifier) GetProtocol() types.Protocol {
	return types.JABBER
}
