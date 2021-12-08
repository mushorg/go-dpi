package ml

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/mushorg/go-dpi/types"
	"github.com/mushorg/go-dpi/utils"
)

var tcpModelFile, udpModelFile string

func init() {
	module := NewLinearSVCModule()
	tcpModelFile, _ = DownloadFileToTemp(module.TCPModelPath, "tcp_model")
	udpModelFile, _ = DownloadFileToTemp(module.UDPModelPath, "udp_model")
}

func TestInitialize(t *testing.T) {
	module := NewLinearSVCModule()
	module.TCPModelPath = tcpModelFile
	module.UDPModelPath = udpModelFile
	if err := module.Initialize(); err != nil {
		t.Error(err)
	}
	module.TCPModelPath = "nonexistent"
	module.UDPModelPath = udpModelFile
	if err := module.Initialize(); err == nil {
		t.Error("Error not thrown for nonexistent TCP model")
	}
	module = NewLinearSVCModule()
	module.TCPModelPath = tcpModelFile
	module.UDPModelPath = "nonexistent"
	if err := module.Initialize(); err == nil {
		t.Error("Error not thrown for nonexistent UDP model")
	}
}

func TestClassifyFlow(t *testing.T) {
	module := NewLinearSVCModule()
	module.TCPModelPath = tcpModelFile
	module.UDPModelPath = udpModelFile
	module.Initialize()
	defer module.Destroy()

	packetChan, err := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}

	httpFlow := types.NewFlow()
	for i := 0; i < 4; i++ {
		packet := <-packetChan
		httpFlow.AddPacket(packet)
	}

	res := module.ClassifyFlow(httpFlow)
	if res.Protocol != types.HTTP {
		t.Errorf("Wrong protocol detected: %v instead of HTTP", res.Protocol)
	}
	if res.Source != MLName {
		t.Errorf("Wrong name: %s instead of %s", res.Source, MLName)
	}

	resAll := module.ClassifyFlowAll(httpFlow)
	if len(resAll) != 1 || resAll[0] != res {
		t.Error("ClassifyFlowAll result inconsistent with ClassifyFlow result")
	}

	for i := 4; i < 12; i++ {
		<-packetChan
	}
	dnsFlow := types.NewFlow()
	dnsPacket := <-packetChan
	dnsFlow.AddPacket(dnsPacket)

	res = module.ClassifyFlow(dnsFlow)
	if res.Protocol != types.DNS {
		t.Errorf("Wrong protocol detected: %v instead of DNS", res.Protocol)
	}
	if res.Source != MLName {
		t.Errorf("Wrong name: %s instead of %s", res.Source, MLName)
	}
}

func TestClassifyFlowEmpty(t *testing.T) {
	module := NewLinearSVCModule()
	module.TCPModelPath = tcpModelFile
	module.UDPModelPath = udpModelFile
	module.Initialize()
	defer module.Destroy()

	res := module.ClassifyFlow(types.NewFlow())
	if res.Protocol != types.Unknown || res.Source != types.NoSource {
		t.Error("Classification result returned on empty flow")
	}
}

func TestMakeFeaturesFromPayload(t *testing.T) {
	payload := "aaabcdef"
	features := MakeFeaturesFromPayload([]byte(payload))
	bytesInt := int32(binary.BigEndian.Uint16([]byte("aa")))
	if count := features[bytesInt+1]; count != 2.0 {
		t.Errorf("Wrong count for bytes 'aa': %f instead of 2.0", count)
	}
	bytesInt = int32(binary.BigEndian.Uint16([]byte("cd")))
	if count := features[bytesInt+1]; count != 1.0 {
		t.Errorf("Wrong count for bytes 'cd': %f instead of 1.0", count)
	}
}

func TestLoadModelFromPath(t *testing.T) {
	if _, err := loadModelFromPath("http://1.1.1.1/model"); err == nil {
		t.Error("Did not get error from downloading from invalid URL")
	}

	module := NewLinearSVCModule()
	os.Setenv("TMPDIR", "/nodir")
	if _, err := loadModelFromPath(module.UDPModelPath); err == nil {
		t.Error("Did not get error from downloading to nonexistent temp dir")
	}

	os.Unsetenv("TMPDIR")
	if _, err := loadModelFromPath(module.UDPModelPath); err != nil {
		t.Error(err)
	}
}

func BenchmarkLinearSVCModule(b *testing.B) {
	module := NewLinearSVCModule()
	module.TCPModelPath = tcpModelFile
	module.UDPModelPath = udpModelFile
	err := types.BenchmarkModule("../../godpi_example/dumps/", module, b.N)
	if err != nil {
		b.Error(err)
	}
}
