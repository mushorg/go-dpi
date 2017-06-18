package godpi

import "github.com/google/gopacket"

// ClassificationSource is the module of the library that is responsible for
// the classification of a flow.
type ClassificationSource string

// NoSource is returned if no classification was made.
const NoSource = ""

// Flow contains sufficient information to classify a flow.
type Flow struct {
	Packets              []*gopacket.Packet
	DetectedProtocol     Protocol
	ClassificationSource ClassificationSource
}

// NewFlow creates an empty flow.
func NewFlow() (flow *Flow) {
	flow = new(Flow)
	flow.Packets = make([]*gopacket.Packet, 0)
	return
}

// CreateFlowFromPacket creates a flow with a single packet.
func CreateFlowFromPacket(packet *gopacket.Packet) (flow *Flow) {
	flow = NewFlow()
	flow.Packets = append(flow.Packets, packet)
	return
}
