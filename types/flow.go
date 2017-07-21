// Package types contains the basic types used by the library.
package types

import "github.com/google/gopacket"

var flowTracker = make(map[gopacket.Flow]*Flow)

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
	flow.AddPacket(packet)
	return
}

// AddPacket adds a new packet to the flow.
func (flow *Flow) AddPacket(packet *gopacket.Packet) {
	newPacket := *packet
	flow.Packets = append(flow.Packets, &newPacket)
}

// GetFlowForPacket finds any previous flow that the packet belongs to. It adds
// the packet to that flow and returns the flow.
// If no such flow is found, a new one is created.
func GetFlowForPacket(packet *gopacket.Packet) (flow *Flow, isNew bool) {
	var ok bool
	isNew = true
	if transport := (*packet).TransportLayer(); transport != nil {
		gpktFlow := transport.TransportFlow()
		srcEp, dstEp := gpktFlow.Endpoints()
		// require a consistent ordering between the endpoints so that packets
		// that go in either direction in the flow will map to the same element
		// in the flowTracker map
		if dstEp.LessThan(srcEp) {
			gpktFlow = gpktFlow.Reverse()
		}
		flow, ok = flowTracker[gpktFlow]
		if ok {
			isNew = false
		} else {
			flow = NewFlow()
			flowTracker[gpktFlow] = flow
		}
		flow.AddPacket(packet)
	} else {
		flow = CreateFlowFromPacket(packet)
	}
	return
}

// FlushTrackedFlows flushes the map used for tracking flows. Any new packets
// that arrive after this operation will be considered new flows.
func FlushTrackedFlows() {
	flowTracker = make(map[gopacket.Flow]*Flow)
}
