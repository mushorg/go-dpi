package classifiers

import (
	"bytes"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
)

// NetBIOSClassifier struct
type NetBIOSClassifier struct{}

func checkTCPNetBIOS(payload []byte, packetsRest []*gopacket.Packet) bool {
	if len(payload) < 8 {
		return false
	}
	nbLen := int(binary.BigEndian.Uint16(payload[2:4]))
	// check for session request
	isSessRequest := payload[0] == 0x81 && payload[1] == 0
	// check for space padding
	names := bytes.Split(payload[4:], []byte{0})
	namesHavePadding := len(names) == 3 && names[0][0] == ' ' && names[1][0] == ' '
	return nbLen+4 == len(payload) && isSessRequest && namesHavePadding
}

func checkUDPNetBIOSWrapper(isFirstPktBroadcast *bool) func([]byte, []*gopacket.Packet) bool {
	return func(payload []byte, packetsRest []*gopacket.Packet) bool {
		// try to detect a name query
		if len(payload) != 50 {
			return false
		}
		// we only detect queries with one question
		hasOneQuestion := bytes.Compare(payload[4:12], []byte{0, 1, 0, 0, 0, 0, 0, 0}) == 0
		// check if the question is a broadcast packet
		isBcastNQ := *isFirstPktBroadcast && payload[2] == 1 && payload[3] == 0x10
		// check if the question is a stat query packet
		isStatNQ := !(*isFirstPktBroadcast) && payload[2] == 0 && payload[3] == 0
		return hasOneQuestion && (isBcastNQ || isStatNQ)
	}
}

// HeuristicClassify for NetBIOSClassifier
func (classifier NetBIOSClassifier) HeuristicClassify(flow *types.Flow) bool {
	var isFirstPktBroadcast bool
	packets := flow.GetPackets()
	if len(packets) > 0 {
		if layer := (*packets[0]).Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer := layer.(*layers.IPv4)
			isFirstPktBroadcast = ipLayer.DstIP[3] == 0xFF
		}
	}
	isNetbiosTCP := checkFirstPayload(packets, layers.LayerTypeTCP,
		checkTCPNetBIOS)
	isNetbiosUDP := checkFirstPayload(packets, layers.LayerTypeUDP,
		checkUDPNetBIOSWrapper(&isFirstPktBroadcast))
	return isNetbiosTCP || isNetbiosUDP
}

// GetProtocol returns the corresponding protocol
func (classifier NetBIOSClassifier) GetProtocol() types.Protocol {
	return types.NetBIOS
}
