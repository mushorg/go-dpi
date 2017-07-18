package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
	"strings"
)

// SSHClassifier struct
type SSHClassifier struct{}

// HeuristicClassify for SSHClassifier
func (_ SSHClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	return checkFirstPayload(flow.Packets, layers.LayerTypeTCP,
		func(payload []byte, _ []*gopacket.Packet) bool {
			payloadStr := string(payload)
			hasSuffix := strings.HasSuffix(payloadStr, "\n")
			hasSSHStr := strings.HasPrefix(payloadStr, "SSH") || strings.Contains(payloadStr, "OpenSSH")
			return hasSuffix && hasSSHStr
		})
}

// GetProtocol returns the corresponding protocol
func (classifier SSHClassifier) GetProtocol() godpi.Protocol {
	return godpi.SSH
}
