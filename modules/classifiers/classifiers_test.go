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
	module := NewClassifierModule()
	dumpPackets, err := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		<-dumpPackets
	}
	packet := <-dumpPackets
	flow := types.CreateFlowFromPacket(&packet)
	result := module.ClassifyFlow(flow)
	flowCls := flow.GetClassificationResult()
	if result.Protocol != types.HTTP || flowCls.Protocol != types.HTTP {
		t.Error("Wrong protocol detected:", result.Protocol)
	}
	if name := flowCls.Source; name != GoDPIName || result.Source != GoDPIName {
		t.Error("Wrong classification source returned:", name)
	}
	results := module.ClassifyFlowAll(flow)
	if len(results) != 1 {
		t.Error("ClassifyFlowAll didn't return one result")
	}
	if results[0] != result {
		t.Errorf("ClassifyFlowAll returned a different result from Classify: %v", results[0])
	}
}

func TestClassifyFlowEmpty(t *testing.T) {
	module := NewClassifierModule()
	flow := types.NewFlow()
	result := module.ClassifyFlow(flow)
	if result.Protocol != types.Unknown || result.Source != types.NoSource {
		t.Error("Protocol incorrectly detected:", result.Protocol)
	}
}

func TestCheckFlowLayer(t *testing.T) {
	dumpPackets, err := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
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
	dumpPackets, err := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	flow := types.NewFlow()
	for packet := range dumpPackets {
		packetCopy := packet
		flow.AddPacket(&packetCopy)
	}

	called := false
	noDetections := checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
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
	module := NewClassifierModule()
	result = make(map[types.Protocol]int)
	packets, err := utils.ReadDumpFile(filename)
	if err != nil {
		return
	}
	for packet := range packets {
		flow, _ := types.GetFlowForPacket(&packet)
		if flow.GetClassificationResult().Protocol == types.Unknown {
			res := module.ClassifyFlow(flow)
			result[res.Protocol]++
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
	types.InitCache(-1)
	defer types.DestroyCache()
	// test for each protocol the expected number of flows in the appropriate capture file
	protocolInfos := []protocolTestInfo{
		{types.HTTP, "../../godpi_example/dumps/http.cap", 2},
		{types.DNS, "../../godpi_example/dumps/dns+icmp.pcapng", 5},
		{types.ICMP, "../../godpi_example/dumps/dns+icmp.pcapng", 22},
		{types.ICMP, "../../godpi_example/dumps/icmpv6.pcap", 49},
		{types.NetBIOS, "../../godpi_example/dumps/netbios.pcap", 12},
		{types.RDP, "../../godpi_example/dumps/rdp.pcap", 2},
		{types.RPC, "../../godpi_example/dumps/dcerpc01.pcap", 3},
		{types.RPC, "../../godpi_example/dumps/dcerpc02.pcap", 1},
		{types.SMB, "../../godpi_example/dumps/smb.cap", 212},
		{types.SSL, "../../godpi_example/dumps/https.cap", 1},
		{types.SSH, "../../godpi_example/dumps/ssh.pcap", 1},
		{types.SMTP, "../../godpi_example/dumps/smtp.pcap", 1},
		{types.FTP, "../../godpi_example/dumps/ftp.pcap", 1},
	}
	for _, info := range protocolInfos {
		count := getPcapDumpProtoMap(info.filename)[info.protocol]
		if count != info.count {
			t.Errorf("Wrong %v packet count in file %s: expected %d, found %d",
				info.protocol, info.filename, info.count, count)
		}
	}
}

func TestConfigureModule(t *testing.T) {
	module := NewClassifierModule()
	dumpPackets, err := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		<-dumpPackets
	}
	packet := <-dumpPackets
	flow := types.CreateFlowFromPacket(&packet)
	result := module.ClassifyFlow(flow)
	if result.Protocol != types.HTTP {
		t.Error("Wrong protocol detected:", result.Protocol)
	}
	module.ConfigureModule(ClassifierModuleConfig{
		Classifiers: []GenericClassifier{},
	})
	result = module.ClassifyFlow(flow)
	if result.Protocol != types.Unknown {
		t.Error("Made detection without any classifiers")
	}
	module.ConfigureModule(ClassifierModuleConfig{
		Classifiers: []GenericClassifier{
			HTTPClassifier{},
		}})
	result = module.ClassifyFlow(flow)
	if result.Protocol != types.HTTP {
		t.Errorf("Wrong protocol detected: %v", result.Protocol)
	}
}

func TestInitDestroy(t *testing.T) {
	module := NewClassifierModule()
	if err := module.Initialize(); err != nil {
		t.Errorf("Initialize returned error: %v", err)
	}
	if err := module.Destroy(); err != nil {
		t.Errorf("Destroy returned error: %v", err)
	}
}

func BenchmarkClassifierModule(b *testing.B) {
	module := NewClassifierModule()
	err := types.BenchmarkModule("../../godpi_example/dumps/", module, b.N)
	if err != nil {
		b.Error(err)
	}
}
