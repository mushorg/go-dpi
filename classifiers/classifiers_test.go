package classifiers

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi"
	"strings"
)

func TestClassifyFlow(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		<-dumpPackets
	}
	packet := <-dumpPackets
	flow := godpi.CreateFlowFromPacket(&packet)
	protocol, source := ClassifyFlow(flow)
	if protocol != godpi.HTTP || flow.DetectedProtocol != godpi.HTTP {
		t.Error("Wrong protocol detected:", protocol)
	}
	if name := flow.ClassificationSource; name != GoDPIName || source != GoDPIName {
		t.Error("Wrong classification source returned:", name)
	}
}

func TestClassifyFlowEmpty(t *testing.T) {
	flow := godpi.NewFlow()
	protocol, source := ClassifyFlow(flow)
	if protocol != godpi.Unknown || source != godpi.NoSource {
		t.Error("Protocol incorrectly detected:", protocol)
	}
}

func TestCheckFlowLayer(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	flow := godpi.NewFlow()
	for packet := range dumpPackets {
		packetCopy := packet
		flow.AddPacket(&packetCopy)
	}
	noDetections := checkFlowLayer(flow, layers.LayerTypeTCP, func(layer gopacket.Layer) bool {
		_, ok := layer.(*layers.TCP)
		if !ok {
			t.Error("Invalid layer passed to callback")
		}
		return false
	})
	if noDetections {
		t.Error("Detection returned true when callback only returns false")
	}

	i := 0
	yesDetections := checkFlowLayer(flow, layers.LayerTypeTCP, func(layer gopacket.Layer) bool {
		i++
		return i == 10
	})
	if !yesDetections {
		t.Error("Detection should have returned true when callback returns true once")
	}
}

func TestCheckFirstPayload(t *testing.T) {
	dumpPackets, err := godpi.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	flow := godpi.NewFlow()
	for packet := range dumpPackets {
		packetCopy := packet
		flow.AddPacket(&packetCopy)
	}

	called := false
	noDetections := checkFirstPayload(flow, layers.LayerTypeTCP, func(payload []byte) bool {
		called = true
		if payload == nil || len(payload) == 0 {
			t.Error("No payload passed to callback")
		}
		if !strings.HasPrefix(string(payload), "GET /download.html") {
			t.Error("Wrong first payload passed to callback")
		}
		return false
	})
	if noDetections {
		t.Error("Detection returned true when callback returned false")
	}
	if !called {
		t.Error("Callback was never called")
	}
}

func getPcapDumpProtoMap(filename string) (result map[godpi.Protocol]int) {
	result = make(map[godpi.Protocol]int)
	packets, err := godpi.ReadDumpFile(filename)
	if err != nil {
		return
	}
	for packet := range packets {
		flow, _ := godpi.GetFlowForPacket(&packet)
		if flow.DetectedProtocol == godpi.Unknown {
			res, _ := ClassifyFlow(flow)
			result[res]++
		}
	}
	return
}

type protocolTestInfo struct {
	protocol godpi.Protocol
	filename string
	count    int
}

func TestClassifiers(t *testing.T) {
	// test for each protocol the expected number of flows in the appropriate capture file
	protocolInfos := []protocolTestInfo{
		{godpi.HTTP, "../godpi_example/dumps/http.cap", 2},
		{godpi.DNS, "../godpi_example/dumps/dns+icmp.pcapng", 5},
		{godpi.ICMP, "../godpi_example/dumps/dns+icmp.pcapng", 22},
		{godpi.ICMP, "../godpi_example/dumps/icmpv6.pcap", 49},
		{godpi.SSL, "../godpi_example/dumps/https.cap", 1},
		{godpi.SSH, "../godpi_example/dumps/ssh.pcap", 1},
	}
	for _, info := range protocolInfos {
		count := getPcapDumpProtoMap(info.filename)[info.protocol]
		if count != info.count {
			t.Errorf("Wrong %s packet count in file %s: expected %d, found %d",
				info.protocol, info.filename, info.count, count)
		}
	}
}
