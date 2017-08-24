// Package ml contains machine learning methods for flow classification.
package ml

import (
	"github.com/google/gopacket/layers"
	"github.com/mushorg/go-dpi/types"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"unsafe"
)

// #cgo LDFLAGS: -llinear
// #include <linear.h>
// #include "liblinear.h"
import "C"

// LinearSVCModule is the module that classifies flows based on a trained
// SVC model.
type LinearSVCModule struct {
	tcpModel, udpModel         *C.struct_model
	Threshold                  float32 // If a prediction has less confidence than this, it is not considered.
	TCPModelPath, UDPModelPath string  // The paths where the liblinear models are stored, for TCP and UDP predictions.
}

// MLName is the name of the machine learning module, to be used as an
// identifier for the source of classification.
const MLName = "godpi-ml"

var detectedProtos = [...]types.Protocol{
	types.HTTP,
	types.DNS,
	types.SSH,
	types.RPC,
	types.SMTP,
	types.RDP,
	types.SMB,
	types.FTP,
	types.SSL,
	types.NetBIOS,
}

// loadModelFromPath takes either a local file path or a URL and tries to load
// the liblinear model from this path. It returns the model or any errors
// that were encountered.
func loadModelFromPath(modelPath string) (*C.struct_model, error) {
	var modelFilePath string
	if strings.HasPrefix(modelPath, "http://") || strings.HasPrefix(modelPath, "https://") {
		// try to fetch file from URL
		resp, err := http.Get(modelPath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		// create temp file to store model
		tmpFile, err := ioutil.TempFile("", "liblinear_model")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()
		io.Copy(tmpFile, resp.Body)
		// the file path to the model is the path of the temp file
		modelFilePath = tmpFile.Name()
	} else {
		// if it's not a URL, it must be a local file path
		modelFilePath = modelPath
	}
	model := C.load_model(C.CString(modelFilePath))
	if model == nil {
		return nil, errors.New("Model could not be loaded: " + modelPath)
	}
	return model, nil
}

// Initialize loads the files that contain the SVC models used for classification.
func (module *LinearSVCModule) Initialize() error {
	var err error
	module.tcpModel, err = loadModelFromPath(module.TCPModelPath)
	if err != nil {
		return err
	}
	module.udpModel, err = loadModelFromPath(module.UDPModelPath)
	if err != nil {
		return err
	}
	return nil
}

// Destroy frees and destroys the loaded models.
func (module *LinearSVCModule) Destroy() error {
	C.free_and_destroy_model(&module.tcpModel)
	C.free_and_destroy_model(&module.udpModel)
	return nil
}

func getFirstClientPayload(flow *types.Flow) (classifyPayload []byte, isTCP bool) {
	packets := flow.GetPackets()
	firstTransport := (*packets[0]).TransportLayer()
	switch transport := firstTransport.(type) {
	case *layers.TCP:
		isTCP = true
		if transport.SYN && !transport.ACK && len(packets) >= 4 {
			clientPort := transport.SrcPort
			for _, pkt := range packets[3:] {
				if pktTCP := (*pkt).Layer(layers.LayerTypeTCP).(*layers.TCP); pktTCP != nil && pktTCP.SrcPort == clientPort {
					if pktPayload := pktTCP.LayerPayload(); pktPayload != nil && len(pktPayload) > 0 {
						classifyPayload = pktPayload
						break
					}
				}
			}
		}
	case *layers.UDP:
		isTCP = false
		for _, pkt := range packets {
			if pktUDP := (*pkt).Layer(layers.LayerTypeUDP).(*layers.UDP); pktUDP != nil {
				if pktPayload := pktUDP.LayerPayload(); pktPayload != nil && len(pktPayload) > 0 {
					classifyPayload = pktPayload
					break
				}
			}
		}
	}
	return
}

// ClassifyFlow creates 2-grams from the given flow's first packet that has a
// payload, and it passes these to liblinear, in order to classify the flow
// using the trained models.
func (module *LinearSVCModule) ClassifyFlow(flow *types.Flow) (result types.ClassificationResult) {
	var model *C.struct_model

	if len(flow.GetPackets()) == 0 {
		return
	}
	payload, isTCP := getFirstClientPayload(flow)
	if payload != nil {
		ngrams := MakeFeaturesFromPayload(payload)

		ngramLen := len(ngrams)
		indexes := make([]int32, 0, ngramLen)
		values := make([]float32, 0, ngramLen)

		for key, val := range ngrams {
			indexes = append(indexes, int32(key))
			values = append(values, val)
		}

		indexesPtr := (*C.int)(unsafe.Pointer(&indexes[0]))
		valuesPtr := (*C.float)(unsafe.Pointer(&values[0]))

		var confidence float32
		confidencePtr := (*C.float)(&confidence)

		if isTCP {
			model = module.tcpModel
		} else {
			model = module.udpModel
		}
		label := C.predict_2grams(model, indexesPtr, valuesPtr, C.int(ngramLen), confidencePtr)

		if confidence >= module.Threshold {
			result.Protocol = detectedProtos[int(label)]
			result.Source = MLName
		}
	}
	return
}

// ClassifyFlowAll returns all the protocols returned by all the ML methods.
func (module *LinearSVCModule) ClassifyFlowAll(flow *types.Flow) []types.ClassificationResult {
	return []types.ClassificationResult{module.ClassifyFlow(flow)}
}

// NewLinearSVCModule returns a new LinearSVCModule with the default configuration.
// By default, the models are downloaded from the project's wiki on initialization,
// and the classification threshold is 0.8.
func NewLinearSVCModule() *LinearSVCModule {
	return &LinearSVCModule{
		TCPModelPath: "https://raw.githubusercontent.com/wiki/mushorg/go-dpi/2grams_tcp.model",
		UDPModelPath: "https://raw.githubusercontent.com/wiki/mushorg/go-dpi/2grams_udp.model",
		Threshold:    0.8,
	}
}

// MakeFeaturesFromPayload creates the 2-grams from the given payload. Each
// key-value pair in the returned map signifies that the (key) 2 byte sequence
// was found (value) times in the payload.
func MakeFeaturesFromPayload(payload []byte) (feats map[int32]float32) {
	feats = make(map[int32]float32)
	for i := 0; i < len(payload)-1; i++ {
		feats[int32(payload[i])*256+int32(payload[i+1])+1]++
	}
	return
}
