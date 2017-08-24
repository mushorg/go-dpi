// Package types contains the basic types used by the library.
package types

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/patrickmn/go-cache"
	"sync"
	"time"
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
	packets        []*gopacket.Packet
	classification ClassificationResult
	mtx            sync.RWMutex
}

// NewFlow creates an empty flow.
func NewFlow() (flow *Flow) {
	flow = new(Flow)
	flow.packets = make([]*gopacket.Packet, 0)
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
	flow.mtx.Lock()
	flow.packets = append(flow.packets, &newPacket)
	flow.mtx.Unlock()
}

// GetPackets returns the list of packets in a thread-safe way.
func (flow *Flow) GetPackets() (packets []*gopacket.Packet) {
	flow.mtx.RLock()
	packets = make([]*gopacket.Packet, len(flow.packets))
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

// GetFlowForPacket finds any previous flow that the packet belongs to. It adds
// the packet to that flow and returns the flow.
// If no such flow is found, a new one is created.
func GetFlowForPacket(packet *gopacket.Packet) (flow *Flow, isNew bool) {
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
		// make sure two simultaneous calls with the same flow string do not
		// create a race condition
		flowTrackerMtx.Lock()
		trackedFlow, ok := flowTracker.Get(gpktFlow.String())
		if ok {
			flow = trackedFlow.(*Flow)
			isNew = false
		} else {
			flow = NewFlow()
		}
		flowTracker.Set(gpktFlow.String(), flow, cache.DefaultExpiration)
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
