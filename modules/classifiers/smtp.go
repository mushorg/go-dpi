package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
	"strings"
)

// SMTPClassifier struct
type SMTPClassifier struct{}

// HeuristicClassify for SMTPClassifier
func (classifier SMTPClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []*gopacket.Packet) bool {
			payloadStr := string(payload)
			for _, line := range strings.Split(payloadStr, "\n") {
				if len(line) > 0 && !strings.HasPrefix(line, "220") {
					return false
				}
			}
			return checkFirstPayload(packetsRest, layers.LayerTypeTCP,
				func(payload []byte, _ []*gopacket.Packet) bool {
					payloadStr := string(payload)
					return (strings.HasPrefix(payloadStr, "EHLO ") ||
						strings.HasPrefix(payloadStr, "HELO ")) &&
						strings.HasSuffix(payloadStr, "\n")
				})
		})
}

// GetProtocol returns the corresponding protocol
func (classifier SMTPClassifier) GetProtocol() types.Protocol {
	return types.SMTP
}
