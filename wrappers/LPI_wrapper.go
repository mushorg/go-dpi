package wrappers

// #cgo CXXFLAGS: -std=c++11
// #cgo LDFLAGS: -lprotoident -ltrace
// #include "LPI_wrapper_impl.hpp"
import "C"
import (
	"github.com/mushorg/go-dpi"
	"unsafe"
)

// lpiCodeToProtocol maps the LPI protocol codes to go-dpi protocols.
var lpiCodeToProtocol = map[uint32]godpi.Protocol{
	0:   godpi.Http,     // LPI_PROTO_HTTP
	14:  godpi.Dns,      // LPI_PROTO_DNS
	201: godpi.Dns,      // LPI_PROTO_UDP_DNS
	8:   godpi.Ssh,      // LPI_PROTO_SSH
	23:  godpi.Rpc,      // LPI_PROTO_RPC_SCAN
	1:   godpi.Smtp,     // LPI_PROTO_SMTP
	92:  godpi.Smtp,     // LPI_PROTO_INVALID_SMTP
	21:  godpi.Rdp,      // LPI_PROTO_RDP
	24:  godpi.Smb,      // LPI_PROTO_SMB
	380: godpi.Icmp,     // LPI_PROTO_ICMP
	27:  godpi.Ftp,      // LPI_PROTO_FTP_CONTROL
	12:  godpi.Ssl,      // LPI_PROTO_SSL
	37:  godpi.Netbios,  // LPI_PROTO_NETBIOS
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
func (_ *LPIWrapper) GetWrapperName() godpi.ClassificationSource {
	return LPIWrapperName
}
