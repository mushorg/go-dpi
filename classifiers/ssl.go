package classifiers

import (
	"encoding/binary"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
)

// SslClassifier struct
type SslClassifier struct{}

// HeuristicClassify for SslClassifier
func (_ SslClassifier) HeuristicClassify(flow *godpi.Flow) bool {
	return checkFirstPayload(flow, layers.LayerTypeTCP, func(payload []byte) (detected bool) {
		if len(payload) >= 9 {
			packetLen := int(binary.BigEndian.Uint16(payload[3:5]))
			clientHelloLenBytes := append([]byte{0}, payload[6:9]...)
			clientHelloLen := int(binary.BigEndian.Uint32(clientHelloLenBytes))
			// check if the packet looks like an SSL/TLS packet
			isSSLProto := payload[0] == 22 && payload[1] <= 3 && packetLen == len(payload[5:])
			// check if the first payload contains a ClientHello message
			isClientHello := payload[5] == 1 && clientHelloLen == len(payload[9:])
			detected = isSSLProto && isClientHello
		}
		return
	})
}

// GetProtocol returns the corresponding protocol
func (classifier SslClassifier) GetProtocol() godpi.Protocol {
	return godpi.Ssl
}
