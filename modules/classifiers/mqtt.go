package classifiers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
	"strings"
)

// MQTTClassifier struct
type MQTTClassifier struct{}

// HeuristicClassify for MQTTClassifier
func (classifier MQTTClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []*gopacket.Packet) bool {
			//check Control packet (connect)
			isValidPacket := payload[0] == 0x10
			//check message lenght
			isValidLenght := int(payload[1]) == len(payload[2:])
			protocolNameStr := string(payload[4:])
			//check protocol name
			isValidMQTT := strings.HasPrefix(protocolNameStr, "MQ")
			return isValidMQTT && isValidLenght && isValidPacket
		})
}

// GetProtocol returns the corresponding protocol
func (classifier MQTTClassifier) GetProtocol() types.Protocol {
	return types.MQTT
}
