package godpi

import "github.com/google/gopacket"

// Flow contains sufficient information to classify a flow.
type Flow struct {
	Packets []*gopacket.Packet
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
