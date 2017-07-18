package classifiers

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
	"strings"
)

func TestClassifyFlow(t *testing.T) {
	dumpPackets, err := utils.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		<-dumpPackets
	}
	packet := <-dumpPackets
	flow := types.CreateFlowFromPacket(&packet)
	protocol, source := ClassifyFlow(flow)
	if protocol != types.HTTP || flow.DetectedProtocol != types.HTTP {
		t.Error("Wrong protocol detected:", protocol)
	}
	if name := flow.ClassificationSource; name != GoDPIName || source != GoDPIName {
		t.Error("Wrong classification source returned:", name)
	}
}

func TestClassifyFlowEmpty(t *testing.T) {
	flow := types.NewFlow()
	protocol, source := ClassifyFlow(flow)
	if protocol != types.Unknown || source != types.NoSource {
		t.Error("Protocol incorrectly detected:", protocol)
	}
}

func TestCheckFlowLayer(t *testing.T) {
	dumpPackets, err := utils.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	flow := types.NewFlow()
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
	dumpPackets, err := utils.ReadDumpFile("../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	flow := types.NewFlow()
	for packet := range dumpPackets {
		packetCopy := packet
		flow.AddPacket(&packetCopy)
	}

	called := false
	noDetections := checkFirstPayload(flow.Packets, layers.LayerTypeTCP,
		func(payload []byte, packetsRest []*gopacket.Packet) bool {
			called = true
			if payload == nil || len(payload) == 0 {
				t.Error("No payload passed to callback")
			}
			if !strings.HasPrefix(string(payload), "GET /download.html") {
				t.Error("Wrong first payload passed to callback")
			}
			if len(packetsRest) != 39 {
				t.Error(len(packetsRest))
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

func getPcapDumpProtoMap(filename string) (result map[types.Protocol]int) {
	result = make(map[types.Protocol]int)
	packets, err := utils.ReadDumpFile(filename)
	if err != nil {
		return
	}
	for packet := range packets {
		flow, _ := types.GetFlowForPacket(&packet)
		if flow.DetectedProtocol == types.Unknown {
			res, _ := ClassifyFlow(flow)
			result[res]++
		}
	}
	return
}

type protocolTestInfo struct {
	protocol types.Protocol
	filename string
	count    int
}

func TestClassifiers(t *testing.T) {
	// test for each protocol the expected number of flows in the appropriate capture file
	protocolInfos := []protocolTestInfo{
		{types.HTTP, "../godpi_example/dumps/http.cap", 2},
		{types.DNS, "../godpi_example/dumps/dns+icmp.pcapng", 5},
		{types.ICMP, "../godpi_example/dumps/dns+icmp.pcapng", 22},
		{types.ICMP, "../godpi_example/dumps/icmpv6.pcap", 49},
		{types.SSL, "../godpi_example/dumps/https.cap", 1},
		{types.SSH, "../godpi_example/dumps/ssh.pcap", 1},
		{types.SMTP, "../godpi_example/dumps/smtp.pcap", 1},
		{types.FTP, "../godpi_example/dumps/ftp.pcap", 1},
	}
	for _, info := range protocolInfos {
		count := getPcapDumpProtoMap(info.filename)[info.protocol]
		if count != info.count {
			t.Errorf("Wrong %s packet count in file %s: expected %d, found %d",
				info.protocol, info.filename, info.count, count)
		}
	}
}
