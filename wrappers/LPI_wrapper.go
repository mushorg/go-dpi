package wrappers

// #cgo CXXFLAGS: -std=c++11
// #cgo LDFLAGS: -lprotoident -ltrace
// #include "LPI_wrapper_impl.hpp"
import "C"
import (
	"unsafe"

	"github.com/mushorg/go-dpi"
)

// lpiCodeToProtocol maps the LPI protocol codes to go-dpi protocols.
var lpiCodeToProtocol = map[uint32]godpi.Protocol{
	0:   godpi.HTTP,    // LPI_PROTO_HTTP
	14:  godpi.DNS,     // LPI_PROTO_DNS
	201: godpi.DNS,     // LPI_PROTO_UDP_DNS
	8:   godpi.SSH,     // LPI_PROTO_SSH
	23:  godpi.RPC,     // LPI_PROTO_RPC_SCAN
	1:   godpi.SMTP,    // LPI_PROTO_SMTP
	92:  godpi.SMTP,    // LPI_PROTO_INVALID_SMTP
	21:  godpi.RDP,     // LPI_PROTO_RDP
	24:  godpi.SMB,     // LPI_PROTO_SMB
	380: godpi.ICMP,    // LPI_PROTO_ICMP
	27:  godpi.FTP,     // LPI_PROTO_FTP_CONTROL
	12:  godpi.SSL,     // LPI_PROTO_SSL
	37:  godpi.NetBIOS, // LPI_PROTO_NETBIOS
}

// LPIWrapperName is the identification of the libprotoident library.
const LPIWrapperName = "libprotoident"

// LPIWrapper is the wrapper for the LPI protocol identification library,
// providing the methods used to interface with it from go-dpi.
type LPIWrapper struct{}

// NewLPIWrapper constructs a new LPIWrapper.
func NewLPIWrapper() *LPIWrapper {
	return &LPIWrapper{}
}

// InitializeWrapper initializes the libprotoident wrapper.
func (wrapper *LPIWrapper) InitializeWrapper() error {
	C.lpiInitLibrary()
	return nil
}

// DestroyWrapper destroys the libprotoident wrapper.
func (wrapper *LPIWrapper) DestroyWrapper() error {
	C.lpiDestroyLibrary()
	return nil
}

// ClassifyFlow classifies a flow using the libprotoident library. It returns
// the detected protocol and any error.
func (wrapper *LPIWrapper) ClassifyFlow(flow *godpi.Flow) (godpi.Protocol, error) {
	lpiFlow := C.lpiCreateFlow()
	defer C.lpiFreeFlow(lpiFlow)
	for _, packet := range flow.Packets {
		pktData := (*packet).Data()
		dataPtr := unsafe.Pointer(&pktData[0])
		C.lpiAddPacketToFlow(lpiFlow, dataPtr, C.ushort(len(pktData)))
	}
	lpiProto := uint32(C.lpiGuessProtocol(lpiFlow))
	if proto, found := lpiCodeToProtocol[lpiProto]; found {
		return proto, nil
	}
	return godpi.Unknown, nil
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *LPIWrapper) GetWrapperName() godpi.ClassificationSource {
	return LPIWrapperName
}
