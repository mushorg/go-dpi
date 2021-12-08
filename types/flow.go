// Package types contains the basic types used by the library.
package types

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/patrickmn/go-cache"
)

var flowTracker *cache.Cache
var flowTrackerMtx sync.Mutex

// ClassificationSource is the module of the library that is responsible for
// the classification of a flow.
type ClassificationSource string

// ClassificationResult contains the detected protocol and the source of
// the classification from a classification attempt.
type ClassificationResult struct {
	Protocol Protocol
	Source   ClassificationSource
}

func (result ClassificationResult) String() string {
	return fmt.Sprintf("Detected protocol %v from source %v", result.Protocol, result.Source)
}

// NoSource is returned if no classification was made.
const NoSource = ""

// Flow contains sufficient information to classify a flow.
type Flow struct {
	packets        []gopacket.Packet
	classification ClassificationResult
	mtx            sync.RWMutex
}

// NewFlow creates an empty flow.
func NewFlow() (flow *Flow) {
	flow = new(Flow)
	flow.packets = make([]gopacket.Packet, 0)
	return
}

// CreateFlowFromPacket creates a flow with a single packet.
func CreateFlowFromPacket(packet gopacket.Packet) (flow *Flow) {
	flow = NewFlow()
	flow.AddPacket(packet)
	return
}

// AddPacket adds a new packet to the flow.
func (flow *Flow) AddPacket(packet gopacket.Packet) {
	flow.mtx.Lock()
	flow.packets = append(flow.packets, packet)
	flow.mtx.Unlock()
}

// GetPackets returns the list of packets in a thread-safe way.
func (flow *Flow) GetPackets() (packets []gopacket.Packet) {
	flow.mtx.RLock()
	packets = make([]gopacket.Packet, len(flow.packets))
	copy(packets, flow.packets)
	flow.mtx.RUnlock()
	return
}

// SetClassificationResult sets the detected protocol and classification source
// for this flow.
func (flow *Flow) SetClassificationResult(protocol Protocol, source ClassificationSource) {
	flow.mtx.Lock()
	flow.classification = ClassificationResult{Protocol: protocol, Source: source}
	flow.mtx.Unlock()
}

// GetClassificationResult returns the currently detected protocol for this
// flow and the source of that detection.
func (flow *Flow) GetClassificationResult() (result ClassificationResult) {
	flow.mtx.RLock()
	result = flow.classification
	flow.mtx.RUnlock()
	return
}

// endpointStrFromFlows creates a string that identifies a flow from the
// network and transport flows of a packet.
func endpointStrFromFlows(networkFlow, transportFlow gopacket.Flow) string {
	srcEp, dstEp := transportFlow.Endpoints()
	// require a consistent ordering between the endpoints so that packets
	// that go in either direction in the flow will map to the same element
	// in the flowTracker map
	if dstEp.LessThan(srcEp) {
		networkFlow = networkFlow.Reverse()
		transportFlow = transportFlow.Reverse()
	}
	gpktIp1, gpktIp2 := networkFlow.Endpoints()
	gpktPort1, gpktPort2 := transportFlow.Endpoints()
	return fmt.Sprintf("%s:%s,%s:%s", gpktIp1, gpktPort1.String(), gpktIp2, gpktPort2.String())
}

// GetFlowForPacket finds any previous flow that the packet belongs to. It adds
// the packet to that flow and returns the flow.
// If no such flow is found, a new one is created.
func GetFlowForPacket(packet gopacket.Packet) (flow *Flow, isNew bool) {
	isNew = true
	network := packet.NetworkLayer()
	transport := packet.TransportLayer()
	if network != nil && transport != nil {
		gpktNetworkFlow := network.NetworkFlow()
		gpktTransportFlow := transport.TransportFlow()
		flowStr := endpointStrFromFlows(gpktNetworkFlow, gpktTransportFlow)
		// make sure two simultaneous calls with the same flow string do not
		// create a race condition
		flowTrackerMtx.Lock()
		trackedFlow, ok := flowTracker.Get(flowStr)
		if ok {
			flow = trackedFlow.(*Flow)
			isNew = false
		} else {
			flow = NewFlow()
		}
		flowTracker.Set(flowStr, flow, cache.DefaultExpiration)
		flowTrackerMtx.Unlock()
		flow.AddPacket(packet)
	} else {
		flow = CreateFlowFromPacket(packet)
	}
	return
}

// FlushTrackedFlows flushes the map used for tracking flows. Any new packets
// that arrive after this operation will be considered new flows.
func FlushTrackedFlows() {
	flowTracker.Flush()
}

// InitCache initializes the flow cache. It must be called before the cache
// is utilised. Flows will be discarded if they are inactive for the given
// duration. If that value is negative, flows will never expire.
func InitCache(expirationTime time.Duration) {
	flowTracker = cache.New(expirationTime, 5*time.Minute)
}

// DestroyCache frees the resources used by the flow cache.
func DestroyCache() {
	if flowTracker != nil {
		flowTracker.Flush()
		flowTracker = nil
	}
}
